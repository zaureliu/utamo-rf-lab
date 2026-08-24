"""Read-only smart card acquisition workflow for Proxmark3.

The workflow never performs key recovery, writes, simulation, replay or raw APDUs.
It identifies the presented card, selects a conservative family-specific plan,
collects all information accessible through read-only commands and forwards any
resulting dump to the unified static analyzer.
"""
from __future__ import annotations

import json
import re
import shutil
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from flask import current_app

from app.config import RUNTIME_DIR
from app.database.db import add_audit, get_connection, get_setting, init_db, now_str, transaction
from app.rf.card_dump_analyzer import build_visual_report, ingest_card_dump, parse_pm3_output
from app.rf.session_manager import add_history, add_session_command, add_session_dump
from app.rf_engine.proxmark3 import executar_comando_sync
from app.services.event_service import add_proxmark_log

SMART_ROOT = (RUNTIME_DIR / "smart_scans").resolve()
SMART_ROOT.mkdir(parents=True, exist_ok=True)
_PORT_LOCKS: dict[str, threading.Lock] = {}
_PORT_LOCKS_GUARD = threading.Lock()

HEX_CLEAN_RE = re.compile(r"[^0-9A-Fa-f]")
UID_PATTERNS = (
    re.compile(r"\bUID\s*[:=.]\s*([0-9A-Fa-f][0-9A-Fa-f :.-]{5,40})", re.I),
    re.compile(r"\bCSN\s*[:=.]\s*([0-9A-Fa-f][0-9A-Fa-f :.-]{5,40})", re.I),
    re.compile(r"\bIDm\s*[:=.]\s*([0-9A-Fa-f][0-9A-Fa-f :.-]{7,40})", re.I),
)
ATQA_RE = re.compile(r"\bATQA\s*[:=.]\s*([0-9A-Fa-f ]{2,12})", re.I)
SAK_RE = re.compile(r"\bSAK\s*[:=.]\s*(?:0x)?([0-9A-Fa-f]{1,4})", re.I)
ATS_RE = re.compile(r"\bATS\s*[:=.]\s*([0-9A-Fa-f ]{2,160})", re.I)
AID_RE = re.compile(r"\b(?:AID|Application ID)\s*[:=.]?\s*(?:0x)?([0-9A-Fa-f]{6})\b", re.I)
PAGE_RE = re.compile(r"^\s*(?:\[?\s*(?:page\s*)?)(\d{1,3})(?:\s*\]?)\s*[:|]\s*((?:[0-9A-Fa-f]{2}[ :]){3}[0-9A-Fa-f]{2})", re.I | re.M)
BLOCK_RE = re.compile(r"^\s*(?:\[?\s*(?:block\s*)?)(\d{1,3})(?:\s*\]?)\s*[:|]\s*((?:[0-9A-Fa-f]{2}[ :]){15}[0-9A-Fa-f]{2})", re.I | re.M)


@dataclass(frozen=True)
class StepSpec:
    stage: str
    command: str
    timeout: int = 45
    optional: bool = True
    capture_dump: bool = False
    description: str = ""


FAMILY_LABELS = {
    "MIFARE_CLASSIC": "MIFARE Classic",
    "MIFARE_ULTRALIGHT": "MIFARE Ultralight / NTAG",
    "MIFARE_PLUS": "MIFARE Plus",
    "MIFARE_DESFIRE": "MIFARE DESFire",
    "NTAG_424": "NTAG 424 DNA",
    "ISO14443_A": "ISO14443-A",
    "ISO14443_B": "ISO14443-B",
    "ISO15693": "ISO15693",
    "FELICA": "FeliCa",
    "TOPAZ": "Topaz / NFC Type 1",
    "UNKNOWN_HF": "HF desconhecido",
}


def _clean_hex(value: str | None) -> str:
    return HEX_CLEAN_RE.sub("", str(value or "")).upper()


def _first(patterns, text: str) -> str:
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            return _clean_hex(match.group(1))
    return ""


def _positive_text(text: str) -> str:
    """Remove probe/no-match lines so `Searching for MIFARE...` is not a detection."""
    excluded = (
        "searching for", "trying to find", "checking for", "no tag", "not found",
        "couldn't identify", "could not identify", "unknown tag", "no known",
    )
    return "\n".join(line for line in str(text or "").splitlines() if not any(item in line.lower() for item in excluded))


def extract_card_facts(text: str) -> dict[str, Any]:
    raw = str(text or "")[:200_000]
    positive = _positive_text(raw)
    low = positive.lower()
    uid = _first(UID_PATTERNS, raw)
    atqa_match = ATQA_RE.search(raw)
    sak_match = SAK_RE.search(raw)
    ats_match = ATS_RE.search(raw)
    atqa = _clean_hex(atqa_match.group(1)) if atqa_match else ""
    sak = _clean_hex(sak_match.group(1)).zfill(2) if sak_match else ""
    ats = _clean_hex(ats_match.group(1)) if ats_match else ""

    family = "UNKNOWN_HF"
    confidence = 0
    evidence: list[str] = []

    def choose(candidate: str, score: int, *why: str) -> None:
        nonlocal family, confidence, evidence
        if score > confidence:
            family, confidence, evidence = candidate, score, [item for item in why if item]

    # Explicit product names are stronger than ATQA/SAK heuristics.
    if any(term in low for term in ("ntag 424", "ntag424", "424 dna")):
        choose("NTAG_424", 100, "identificação explícita NTAG 424")
    if any(term in low for term in ("desfire", "mfdes", "ev1 desfire", "ev2 desfire", "ev3 desfire")):
        choose("MIFARE_DESFIRE", 98, "identificação explícita DESFire")
    if any(term in low for term in ("mifare plus", "security level sl", "mfp")):
        choose("MIFARE_PLUS", 96, "identificação explícita MIFARE Plus")
    if any(term in low for term in ("mifare ultralight", "ultralight ev1", "ultralight c", "ntag21", "ntag 21", "ntag i2c", "hf mfu")):
        choose("MIFARE_ULTRALIGHT", 95, "identificação explícita Ultralight/NTAG")
    if any(term in low for term in ("mifare classic", "crypto1", "static encrypted nonce", "prng................. weak", "hf mf info")):
        choose("MIFARE_CLASSIC", 94, "identificação explícita MIFARE Classic/Crypto1")
    if any(term in low for term in ("iso14443-b", "iso 14443-b", "hf 14b")):
        choose("ISO14443_B", 90, "identificação ISO14443-B")
    if any(term in low for term in ("iso15693", "iso 15693", "vicinity", "icode", "slix")):
        choose("ISO15693", 90, "identificação ISO15693")
    if any(term in low for term in ("felica", "idm", "pmm")):
        choose("FELICA", 90, "identificação FeliCa")
    if any(term in low for term in ("topaz", "jewel", "nfc type 1")):
        choose("TOPAZ", 90, "identificação Topaz")

    # Conservative SAK hints. SAK 0x20 is deliberately kept generic because it
    # is shared by several ISO-DEP products (DESFire, Plus and Type 4 applets).
    sak_int = int(sak, 16) if sak else None
    if sak_int in {0x08, 0x09, 0x18} and confidence < 80:
        choose("MIFARE_CLASSIC", 78, f"SAK 0x{sak}")
    elif sak_int == 0x00 and atqa in {"0044", "4400", "0042", "4200"} and confidence < 75:
        choose("MIFARE_ULTRALIGHT", 72, f"ATQA {atqa} / SAK 00")
    elif sak_int == 0x20 and confidence < 70:
        choose("ISO14443_A", 68, "SAK 0x20 indica ISO-DEP; produto ainda não confirmado")

    if family == "UNKNOWN_HF" and ("iso14443-a" in low or "iso 14443-a" in low or atqa or (uid and sak)):
        choose("ISO14443_A", 60, "anticolisão ISO14443-A")

    random_uid = any(term in low for term in ("random id", "random uid", "rid enabled", "uid is random"))
    card_size = ""
    if any(term in low for term in ("mifare mini", "mini / s20", "320 bytes")):
        card_size = "mini"
    elif any(term in low for term in ("mifare 4k", "classic 4k", "4k / s70", "4096 bytes")):
        card_size = "4k"
    elif any(term in low for term in ("mifare 2k", "classic 2k", "2k card", "2048 bytes")):
        card_size = "2k"
    elif any(term in low for term in ("mifare 1k", "classic 1k", "1k / s50", "1024 bytes")):
        card_size = "1k"

    security_level = ""
    sl_match = re.search(r"\b(?:security\s*level|sl)\s*[:=.]?\s*(SL?[013])\b", positive, re.I)
    if sl_match:
        security_level = sl_match.group(1).upper().replace("S", "SL") if not sl_match.group(1).upper().startswith("SL") else sl_match.group(1).upper()

    aids = sorted({_clean_hex(match) for match in AID_RE.findall(positive) if _clean_hex(match)})
    pages = [{"index": int(index), "hex": _clean_hex(value)} for index, value in PAGE_RE.findall(positive)]
    blocks = [{"index": int(index), "hex": _clean_hex(value)} for index, value in BLOCK_RE.findall(positive)]

    return {
        "family": family,
        "family_label": FAMILY_LABELS.get(family, family),
        "confidence": confidence,
        "evidence": evidence,
        "uid": uid,
        "atqa": atqa,
        "sak": sak,
        "ats": ats,
        "random_uid": random_uid,
        "card_size": card_size,
        "security_level": security_level,
        "aids": aids,
        "pages": pages[:1024],
        "blocks": blocks[:256],
    }


def merge_facts(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    result = dict(base or {})
    if int(extra.get("confidence") or 0) > int(result.get("confidence") or 0):
        for key in ("family", "family_label", "confidence", "evidence"):
            result[key] = extra.get(key)
    for key in ("uid", "atqa", "sak", "ats", "card_size", "security_level"):
        if extra.get(key):
            result[key] = extra[key]
    result["random_uid"] = bool(result.get("random_uid") or extra.get("random_uid"))
    result["aids"] = sorted(set(result.get("aids") or []) | set(extra.get("aids") or []))
    page_map = {int(item["index"]): item for item in (result.get("pages") or []) if "index" in item}
    page_map.update({int(item["index"]): item for item in (extra.get("pages") or []) if "index" in item})
    result["pages"] = [page_map[key] for key in sorted(page_map)]
    block_map = {int(item["index"]): item for item in (result.get("blocks") or []) if "index" in item}
    block_map.update({int(item["index"]): item for item in (extra.get("blocks") or []) if "index" in item})
    result["blocks"] = [block_map[key] for key in sorted(block_map)]
    return result


def _mfc_size_flag(facts: dict[str, Any]) -> str:
    size = str(facts.get("card_size") or "1k").lower()
    return {"mini": "--mini", "2k": "--2k", "4k": "--4k"}.get(size, "--1k")


def build_command_plan(facts: dict[str, Any], job_id: int, options: dict[str, Any]) -> list[StepSpec]:
    family = facts.get("family") or "UNKNOWN_HF"
    read_ndef = bool(options.get("read_ndef", True))
    auto_dump = bool(options.get("auto_dump", True))
    base = f"utamo-smart-{job_id}"
    steps: list[StepSpec] = []

    if family == "MIFARE_CLASSIC":
        steps.append(StepSpec("identify_family", "hf mf info", 55, False, description="Identificar geometria, nonce, fabricante e propriedades Classic"))
        if read_ndef:
            steps.append(StepSpec("read_ndef", "hf mf ndefread", 50, True, description="Tentar leitura NDEF sem alteração"))
        if auto_dump:
            command = f"hf mf dump {_mfc_size_flag(facts)} -f {base}-mfc"
            if options.get("mfc_key_basename"):
                command += f" -k {options['mfc_key_basename']}"
            steps.append(StepSpec("acquire_dump", command, 110, True, True, "Tentar dump usando apenas chaves já disponíveis"))
    elif family == "MIFARE_ULTRALIGHT":
        steps.append(StepSpec("identify_family", "hf mfu info", 55, False, description="Ler tipo, assinatura, locks, contadores e configuração"))
        if read_ndef:
            steps.append(StepSpec("read_ndef", "hf mfu ndefread", 50, True, description="Ler NDEF acessível"))
        if auto_dump:
            steps.append(StepSpec("acquire_dump", f"hf mfu dump -f {base}-mfu -z", 90, True, True, "Ler páginas e salvar BIN/JSON"))
    elif family == "MIFARE_PLUS":
        steps.extend([
            StepSpec("identify_family", "hf mfp info", 55, False, description="Identificar versão e Security Level"),
            StepSpec("read_acl", "hf mfp acl", 50, True, description="Ler condições de acesso disponíveis"),
            StepSpec("read_directory", "hf mfp mad", 45, True, description="Ler MAD acessível"),
        ])
        if read_ndef:
            steps.append(StepSpec("read_ndef", "hf mfp ndefread", 50, True, description="Ler NDEF acessível"))
        if auto_dump:
            steps.append(StepSpec("acquire_dump", "hf mfp dump", 110, True, True, "Tentar dump somente com credenciais/defaults aceitos pelo cartão"))
    elif family == "MIFARE_DESFIRE":
        steps.extend([
            StepSpec("identify_family", "hf mfdes info", 55, False, description="Identificar família DESFire"),
            StepSpec("get_version", "hf mfdes getversion", 45, True, description="Ler versão de hardware/software"),
            StepSpec("get_uid", "hf mfdes getuid", 45, True, description="Ler UID quando permitido"),
            StepSpec("get_memory", "hf mfdes freemem", 45, True, description="Consultar memória livre"),
            StepSpec("list_apps", "hf mfdes getaids", 55, True, description="Listar AIDs acessíveis"),
            StepSpec("list_structure", "hf mfdes lsapp", 80, True, description="Listar aplicações e arquivos acessíveis sem autenticação"),
        ])
    elif family == "NTAG_424":
        steps.append(StepSpec("identify_family", "hf ntag424 info", 55, False, description="Ler versão e configuração pública"))
    elif family == "ISO14443_B":
        steps.append(StepSpec("identify_family", "hf 14b info", 55, False, description="Ler identificação ISO14443-B"))
        if read_ndef:
            steps.append(StepSpec("read_ndef", "hf 14b ndefread", 50, True, description="Tentar NDEF Type 4B"))
    elif family == "ISO15693":
        steps.append(StepSpec("identify_family", "hf 15 info", 55, False, description="Ler UID, AFI, DSFID e IC reference"))
    elif family == "FELICA":
        steps.extend([
            StepSpec("identify_family", "hf felica info", 55, False),
            StepSpec("get_system_codes", "hf felica rqsyscode", 45, True),
            StepSpec("get_response", "hf felica rqresponse", 45, True),
        ])
    elif family == "TOPAZ":
        steps.append(StepSpec("identify_family", "hf topaz info", 55, False))
    elif family == "ISO14443_A":
        # This is deliberately generic. The refinement command may change the
        # classification before this plan is built.
        if read_ndef:
            steps.append(StepSpec("read_ndef", "hf 14a ndefread", 50, True, description="Tentar NDEF Type 4A"))
    return steps


def needs_iso14443a_refinement(facts: dict[str, Any]) -> bool:
    return facts.get("family") in {"ISO14443_A", "UNKNOWN_HF"} and bool(facts.get("uid") or facts.get("atqa"))


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _load_json(value: Any, default):
    try:
        return json.loads(value) if isinstance(value, str) and value else default
    except (TypeError, ValueError, json.JSONDecodeError):
        return default


def create_smart_scan(options: dict[str, Any] | None = None) -> int:
    init_db()
    opts = dict(options or {})
    with transaction() as conn:
        cur = conn.execute(
            """INSERT INTO smart_scan_jobs(status,stage,progress,options_json,result_json,created_at,updated_at)
               VALUES (?,?,?,?,?,?,?)""",
            ("queued", "queued", 0, _json(opts), "{}", now_str(), now_str()),
        )
        return int(cur.lastrowid)


def _job_row(job_id: int):
    conn = get_connection()
    try:
        return conn.execute("SELECT * FROM smart_scan_jobs WHERE id=?", (int(job_id),)).fetchone()
    finally:
        conn.close()


def get_smart_scan(job_id: int, include_outputs: bool = False) -> dict[str, Any] | None:
    row = _job_row(job_id)
    if not row:
        return None
    result = dict(row)
    result["options"] = _load_json(result.pop("options_json", "{}"), {})
    result["result"] = _load_json(result.pop("result_json", "{}"), {})
    conn = get_connection()
    try:
        columns = "id,job_id,step_index,stage,command,status,output,parsed_json,started_at,finished_at" if include_outputs else "id,job_id,step_index,stage,command,status,output_excerpt,parsed_json,started_at,finished_at"
        # ``columns`` is selected exclusively from the two literals above; no request data enters the SQL structure.
        rows = conn.execute(
            f"SELECT {columns} FROM smart_scan_steps WHERE job_id=? ORDER BY step_index,id",  # noqa: S608
            (int(job_id),),
        ).fetchall()
        steps = []
        for item in rows:
            step = dict(item)
            step["parsed"] = _load_json(step.pop("parsed_json", "{}"), {})
            steps.append(step)
        result["steps"] = steps
    finally:
        conn.close()
    result["terminal"] = result.get("status") in {"completed", "partial", "failed", "cancelled"}
    return result


def list_smart_scans(limit: int = 50) -> list[dict[str, Any]]:
    init_db()
    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT id,status,stage,progress,uid,family,card_type,acquisition_status,dump_id,error,created_at,updated_at
               FROM smart_scan_jobs ORDER BY id DESC LIMIT ?""",
            (max(1, min(500, int(limit or 50))),),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def recover_interrupted_smart_scans() -> int:
    """Close jobs left non-terminal after an application restart or crash."""
    message = "Leitura interrompida porque a aplicação foi reiniciada antes da conclusão."
    with transaction() as conn:
        cur = conn.execute(
            """UPDATE smart_scan_jobs
               SET status='failed',stage='interrupted',progress=100,error=?,updated_at=?
               WHERE status IN ('queued','waiting','running')""",
            (message, now_str()),
        )
        count = int(cur.rowcount or 0)
    if count:
        add_audit("local", "pm3.smart_scan.recovery", "startup", "closed", f"jobs={count}")
    return count


def request_cancel(job_id: int) -> bool:
    with transaction() as conn:
        cur = conn.execute(
            """UPDATE smart_scan_jobs SET cancel_requested=1,updated_at=?
               WHERE id=? AND status NOT IN ('completed','partial','failed','cancelled')""",
            (now_str(), int(job_id)),
        )
        return cur.rowcount > 0


def _cancel_requested(job_id: int) -> bool:
    row = _job_row(job_id)
    return bool(row and row["cancel_requested"])


def _update_job(job_id: int, **fields) -> None:
    if not fields:
        return
    fields["updated_at"] = now_str()
    allowed = {
        "status", "stage", "progress", "uid", "family", "card_type", "acquisition_status",
        "dump_id", "error", "result_json", "cancel_requested", "updated_at",
    }
    values = {key: value for key, value in fields.items() if key in allowed}
    assignments = ",".join(f"{key}=?" for key in values)
    with transaction() as conn:
        # Column names come from the fixed ``allowed`` set and values remain parameterized.
        conn.execute(
            f"UPDATE smart_scan_jobs SET {assignments} WHERE id=?",  # noqa: S608
            (*values.values(), int(job_id)),
        )


def _add_step(job_id: int, index: int, spec: StepSpec) -> int:
    with transaction() as conn:
        cur = conn.execute(
            """INSERT INTO smart_scan_steps(job_id,step_index,stage,command,status,output,output_excerpt,parsed_json,started_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (job_id, index, spec.stage, spec.command, "running", "", "", "{}", now_str()),
        )
        return int(cur.lastrowid)


def _finish_step(step_id: int, status: str, output: str, parsed: dict[str, Any]) -> None:
    clean_output = str(output or "")[:250_000]
    excerpt = clean_output[-8000:]
    with transaction() as conn:
        conn.execute(
            """UPDATE smart_scan_steps SET status=?,output=?,output_excerpt=?,parsed_json=?,finished_at=? WHERE id=?""",
            (status, clean_output, excerpt, _json(parsed), now_str(), int(step_id)),
        )


def _port_lock(port: str) -> threading.Lock:
    with _PORT_LOCKS_GUARD:
        return _PORT_LOCKS.setdefault(str(port).upper(), threading.Lock())


def _log_executor_result(result: dict[str, Any], session_id: int | None = None, port: str = "", command: str = "") -> None:
    for item in result.get("logs", []):
        add_proxmark_log({
            "port": item.get("port") or port,
            "command": item.get("command") or command,
            "status": item.get("status"),
            "output": item.get("output"),
            "timestamp": item.get("timestamp"),
        })
    add_history(port, command, result.get("status"))
    if session_id:
        try:
            add_session_command(session_id, port, command, result.get("status"), result.get("output") or "", extract_card_facts(result.get("output") or ""))
        except Exception:
            pass


def _copy_optional_key_file(workspace: Path, options: dict[str, Any]) -> dict[str, Any]:
    configured = str(options.get("mfc_key_file") or get_setting("mfc_key_file", "")).strip().strip('"')
    if not configured:
        return options
    source = Path(configured).expanduser().resolve()
    if not source.is_file() or source.stat().st_size > 1024 * 1024:
        options["mfc_key_warning"] = "Arquivo de chaves configurado não existe ou excede 1 MiB; ignorado."
        return options
    if source.suffix.lower() not in {".bin", ".key", ".keys"}:
        options["mfc_key_warning"] = "Formato de arquivo de chaves não aceito para dump; use BIN/KEYS."
        return options
    target = workspace / "mfc-keys.bin"
    shutil.copyfile(source, target)
    options["mfc_key_basename"] = target.name
    return options


def _new_dump_files(workspace: Path, previous: set[Path]) -> list[Path]:
    allowed = {".json", ".bin", ".mfu", ".dump", ".mfd", ".eml"}
    current = {path.resolve() for path in workspace.iterdir() if path.is_file() and path.suffix.lower() in allowed}
    return sorted(current - previous, key=lambda path: path.stat().st_mtime)


def _pick_dump_file(files: list[Path]) -> Path | None:
    files = [path for path in files if "key" not in path.name.lower() and path.stat().st_size > 0]
    if not files:
        return None
    order = {".json": 0, ".mfu": 1, ".bin": 2, ".mfd": 3, ".dump": 4, ".eml": 5}
    return sorted(files, key=lambda path: (order.get(path.suffix.lower(), 99), -path.stat().st_size))[0]


def _classify_dump_acquisition(facts: dict[str, Any], analysis_result: dict[str, Any]) -> str:
    analysis = analysis_result.get("analysis") or {}
    count = int(analysis.get("block_count") or 0)
    if count <= 0:
        return "metadata_only"
    card_type = str(analysis.get("card_type") or "").lower()
    if "partial" in card_type or "non-standard" in card_type:
        return "partial_dump"
    expected_by_type = {
        "mifare classic mini": 20,
        "mifare classic 1k": 64,
        "mifare classic 2k": 128,
        "mifare classic 4k": 256,
    }
    expected = expected_by_type.get(card_type)
    if expected is not None:
        return "complete_dump" if count == expected else "partial_dump"
    # Type 2 and logical products have variable memory/application sizes. A file
    # was acquired and normalized, but completeness cannot be asserted statically.
    return "dump_acquired"


def _write_evidence(workspace: Path, payload: dict[str, Any]) -> Path:
    path = workspace / "workflow-evidence.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _run_step(
    job_id: int,
    index: int,
    spec: StepSpec,
    client_path: str,
    port: str,
    workspace: Path,
    executor: Callable[..., dict[str, Any]],
    session_id: int | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    step_id = _add_step(job_id, index, spec)
    result = executor(
        client_path,
        spec.command,
        port,
        timeout=spec.timeout,
        confirm_sensitive=False,
        working_directory=workspace,
        policy_context="smart_acquisition",
        cancel_check=lambda: _cancel_requested(job_id),
    )
    output = result.get("output") or ""
    parsed = extract_card_facts(output)
    _finish_step(step_id, result.get("status") or "error", output, parsed)
    _log_executor_result(result, session_id, port, spec.command)
    return result, parsed


def _finish_early_cancellation(
    job_id: int, workspace: Path, facts: dict[str, Any], outputs: list[dict[str, Any]], command_count: int
) -> dict[str, Any] | None:
    error = "Leitura cancelada pelo operador."
    payload = {
        "job_id": job_id,
        "facts": facts,
        "commands_executed": command_count,
        "commands_succeeded": sum(item.get("status") == "ok" for item in outputs),
        "acquisition_status": "cancelled",
        "dump_id": None,
        "workspace": str(workspace),
    }
    try:
        evidence = _write_evidence(workspace, {**payload, "error": error, "steps": outputs})
        payload["evidence_file"] = evidence.name
    except OSError:
        pass
    _update_job(
        job_id, status="cancelled", stage="cancelled", progress=100,
        uid=facts.get("uid"), family=facts.get("family"), card_type=facts.get("family_label"),
        acquisition_status="cancelled", error=error, result_json=_json(payload),
    )
    add_audit("local", "pm3.smart_scan", str(job_id), "cancelled", f"family={facts.get('family')}")
    return get_smart_scan(job_id)


def run_smart_scan(job_id: int, executor: Callable[..., dict[str, Any]] = executar_comando_sync) -> dict[str, Any] | None:
    """Run a queued job in the current Flask application context."""
    try:
        return _run_smart_scan_locked(job_id, executor)
    except Exception as exc:
        # Pre-flight failures (workspace/key file/DB) happen before the guarded
        # section; the job must never stay queued/waiting after a 202 response.
        try:
            _update_job(
                job_id, status="failed", stage="failed", progress=100,
                acquisition_status="none", error=str(exc), result_json=_json({"job_id": job_id}),
            )
            add_audit("local", "pm3.smart_scan", str(job_id), "failed", f"pre-flight: {exc}")
        except Exception:
            pass
        return get_smart_scan(job_id)


def _run_smart_scan_locked(job_id: int, executor: Callable[..., dict[str, Any]]) -> dict[str, Any] | None:
    job = get_smart_scan(job_id)
    if not job:
        return None
    options = dict(job.get("options") or {})
    client_path = get_setting("proxmark_client_path", "")
    port = get_setting("proxmark_port", "COM5")
    session_id = options.get("session_id")
    try:
        session_id = int(session_id) if session_id else None
    except (TypeError, ValueError):
        session_id = None

    workspace_root = Path(current_app.config.get("SMART_SCAN_DIR", SMART_ROOT)).expanduser().resolve()
    workspace_root.mkdir(parents=True, exist_ok=True)
    workspace = (workspace_root / f"scan-{job_id:06d}").resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    options = _copy_optional_key_file(workspace, options)
    max_commands = int(current_app.config.get("SMART_SCAN_MAX_COMMANDS", 12))
    total_timeout = int(current_app.config.get("SMART_SCAN_TOTAL_TIMEOUT", 480))
    enforce_uid = bool(options.get("enforce_uid", True))
    deadline = time.monotonic() + total_timeout
    facts: dict[str, Any] = {"family": "UNKNOWN_HF", "family_label": FAMILY_LABELS["UNKNOWN_HF"], "confidence": 0, "aids": [], "pages": [], "blocks": []}
    outputs: list[dict[str, Any]] = []
    generated_files: list[Path] = []
    command_count = 0
    dump_id = None
    status = "failed"
    acquisition_status = "none"
    error = ""

    lock = _port_lock(port)
    _update_job(job_id, status="waiting", stage="waiting_for_port", progress=2)
    with lock:
        _update_job(job_id, status="running", stage="searching", progress=5)
        try:
            # Required initial search.
            search_spec = StepSpec("searching", "hf search", 70, False, description="Busca geral de tags HF")
            result, parsed = _run_step(job_id, 1, search_spec, client_path, port, workspace, executor, session_id)
            command_count += 1
            outputs.append({"command": search_spec.command, "status": result.get("status"), "output": result.get("output") or ""})
            facts = merge_facts(facts, parsed)
            if result.get("status") == "cancelled":
                status = "cancelled"
                acquisition_status = "cancelled"
                error = "Leitura cancelada pelo operador."
            elif result.get("status") != "ok":
                raise RuntimeError("hf search não foi concluído com sucesso.")
            if status == "cancelled":
                return _finish_early_cancellation(job_id, workspace, facts, outputs, command_count)
            if not facts.get("uid") and facts.get("family") == "UNKNOWN_HF":
                raise RuntimeError("Nenhum cartão HF reconhecido. Mantenha o cartão estável sobre a antena e tente novamente.")

            initial_uid = facts.get("uid") or ""
            _update_job(job_id, uid=initial_uid, family=facts.get("family"), card_type=facts.get("family_label"), stage="classifying", progress=16)

            # ISO14443-A refinement is a separate safe command because hf search
            # often returns only anticollision fields.
            if needs_iso14443a_refinement(facts) and command_count < max_commands:
                refine_spec = StepSpec("refining", "hf 14a info", 55, False, description="Refinar tecnologia ISO14443-A")
                result, parsed = _run_step(job_id, 2, refine_spec, client_path, port, workspace, executor, session_id)
                command_count += 1
                outputs.append({"command": refine_spec.command, "status": result.get("status"), "output": result.get("output") or ""})
                facts = merge_facts(facts, parsed)
                if result.get("status") == "cancelled":
                    return _finish_early_cancellation(job_id, workspace, facts, outputs, command_count)
                if result.get("status") != "ok":
                    raise RuntimeError("A identificação ISO14443-A falhou.")
                current_uid = parsed.get("uid")
                if enforce_uid and initial_uid and current_uid and current_uid != initial_uid and not facts.get("random_uid"):
                    raise RuntimeError(f"O cartão mudou durante a leitura ({initial_uid} → {current_uid}).")

            plan = build_command_plan(facts, job_id, options)
            remaining = max(0, max_commands - command_count)
            plan = plan[:remaining]
            total_steps = max(1, len(plan))
            base_index = command_count + 1

            for offset, spec in enumerate(plan):
                if _cancel_requested(job_id):
                    status = "cancelled"
                    acquisition_status = "cancelled"
                    error = "Leitura cancelada pelo operador."
                    break
                if time.monotonic() >= deadline:
                    status = "partial"
                    acquisition_status = "partial"
                    error = "Tempo total da leitura inteligente excedido."
                    break
                progress = 22 + int((offset / total_steps) * 58)
                _update_job(job_id, stage=spec.stage, progress=progress, family=facts.get("family"), card_type=facts.get("family_label"), uid=facts.get("uid"))
                before_files = {path.resolve() for path in workspace.iterdir() if path.is_file()}
                result, parsed = _run_step(job_id, base_index + offset, spec, client_path, port, workspace, executor, session_id)
                command_count += 1
                outputs.append({"command": spec.command, "status": result.get("status"), "output": result.get("output") or ""})
                facts = merge_facts(facts, parsed)
                if result.get("status") == "cancelled":
                    status = "cancelled"
                    acquisition_status = "cancelled"
                    error = "Leitura cancelada pelo operador."
                    break

                current_uid = parsed.get("uid")
                if enforce_uid and initial_uid and current_uid and current_uid != initial_uid and not facts.get("random_uid"):
                    status = "failed"
                    acquisition_status = "aborted_card_changed"
                    error = f"O cartão foi removido ou trocado durante a leitura ({initial_uid} → {current_uid})."
                    break
                if spec.capture_dump:
                    generated_files.extend(_new_dump_files(workspace, before_files))
                if result.get("status") not in {"ok", "timeout"} and not spec.optional:
                    raise RuntimeError(f"Etapa obrigatória falhou: {spec.command}")

            if status != "cancelled" and acquisition_status != "aborted_card_changed":
                _update_job(job_id, stage="analyzing", progress=84)
                selected = _pick_dump_file(generated_files)
                if selected:
                    try:
                        analysis = ingest_card_dump(selected.name, selected.read_bytes(), f"Smart scan #{job_id} — {facts.get('family_label')}")
                        dump_id = int(analysis.get("dump_id"))
                        acquisition_status = _classify_dump_acquisition(facts, analysis)
                        status = "completed"
                        if session_id:
                            add_session_dump(session_id, dump_id)
                    except Exception as exc:
                        acquisition_status = "partial_dump_error"
                        status = "partial"
                        error = f"O dump foi produzido, mas o analisador não conseguiu importá-lo: {exc}"
                else:
                    successful = sum(item.get("status") == "ok" for item in outputs)
                    acquisition_status = "metadata_only" if successful else "none"
                    status = "partial" if successful else "failed"
                    if not error and facts.get("family") in {"MIFARE_CLASSIC", "MIFARE_PLUS"} and options.get("auto_dump", True):
                        error = "Identificação concluída, mas não foi possível obter dump completo com as chaves já disponíveis."

            combined_output = "\n\n".join(f"### {item['command']}\n{item['output']}" for item in outputs)
            try:
                if combined_output:
                    parse_pm3_output(combined_output)
            except Exception:
                pass

            report = build_visual_report(dump_id) if dump_id else None
            result_payload = {
                "job_id": job_id,
                "facts": facts,
                "commands_executed": command_count,
                "commands_succeeded": sum(item.get("status") == "ok" for item in outputs),
                "acquisition_status": acquisition_status,
                "dump_id": dump_id,
                "dump_summary": (report or {}).get("dump") if isinstance(report, dict) else None,
                "warnings": [value for key, value in options.items() if key.endswith("_warning") and value],
                "workspace": str(workspace),
            }
            evidence_path = _write_evidence(workspace, {**result_payload, "steps": outputs})
            result_payload["evidence_file"] = evidence_path.name
            final_progress = 100 if status in {"completed", "partial", "cancelled"} else 95
            _update_job(
                job_id,
                status=status,
                stage="finished" if status != "cancelled" else "cancelled",
                progress=final_progress,
                uid=facts.get("uid"),
                family=facts.get("family"),
                card_type=facts.get("family_label"),
                acquisition_status=acquisition_status,
                dump_id=dump_id,
                error=error,
                result_json=_json(result_payload),
            )
            add_audit("local", "pm3.smart_scan", str(job_id), status, f"family={facts.get('family')}; dump_id={dump_id}; acquisition={acquisition_status}")
        except Exception as exc:
            error = str(exc)
            result_payload = {
                "job_id": job_id,
                "facts": facts,
                "commands_executed": command_count,
                "acquisition_status": acquisition_status,
                "dump_id": dump_id,
            }
            try:
                _write_evidence(workspace, {**result_payload, "error": error, "steps": outputs})
            except OSError:
                pass
            _update_job(
                job_id,
                status="failed",
                stage="failed",
                progress=100,
                uid=facts.get("uid"),
                family=facts.get("family"),
                card_type=facts.get("family_label"),
                acquisition_status=acquisition_status,
                dump_id=dump_id,
                error=error,
                result_json=_json(result_payload),
            )
            add_audit("local", "pm3.smart_scan", str(job_id), "failed", error)
    return get_smart_scan(job_id)


def launch_smart_scan(app, job_id: int) -> threading.Thread:
    def worker() -> None:
        with app.app_context():
            run_smart_scan(job_id)

    thread = threading.Thread(target=worker, name=f"utamo-smart-scan-{job_id}", daemon=True)
    thread.start()
    return thread


def smart_scan_public_payload(job: dict[str, Any] | None) -> dict[str, Any] | None:
    if not job:
        return None
    payload = dict(job)
    if isinstance(payload.get("options"), dict):
        payload["options"] = dict(payload["options"])
        payload["options"].pop("mfc_key_file", None)
        payload["options"].pop("mfc_key_basename", None)
    # Do not expose local paths through the API.
    if isinstance(payload.get("result"), dict):
        payload["result"] = dict(payload["result"])
        payload["result"].pop("workspace", None)
    return payload
