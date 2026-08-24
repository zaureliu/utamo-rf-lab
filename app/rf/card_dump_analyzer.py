"""Unified static RFID/MIFARE dump analysis engine.

The module intentionally separates static evidence from operational conclusions.
A dump can show weak keys or reproducible data, but it cannot by itself prove that
an application credential is clonable or that a UID is writable.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import statistics
import uuid
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any

from app.config import RUNTIME_DIR
from app.database.db import get_conn, init_db, transaction
from app.rf.access_bits import decode_access_conditions, decode_sector_trailer
from app.rf.ndef_decoder import decode_ndef_from_units
from app.rf.protocol_catalog import suggest_protocol_from_text

DATA_DIR = Path(os.environ.get("UTAMO_RF_DATA_DIR") or RUNTIME_DIR / "data").resolve()
DUMP_DIR = DATA_DIR / "rfid_dumps"
REPORT_DIR = DATA_DIR / "rfid_reports"
DUMP_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

MIFARE_1K_BLOCKS = 64
MIFARE_2K_BLOCKS = 128
MIFARE_4K_BLOCKS = 256
MFU_NEW_PREFIX = 56
MFU_OLD_PREFIX = 48

DEFAULT_KEYS = {
    "FFFFFFFFFFFF": "Factory default",
    "000000000000": "Blank/null key",
    "A0A1A2A3A4A5": "MIFARE Application Directory public Key A",
    "A5A4A3A2A1A0": "MAD key reversed/test",
    "89ECA97F8C2A": "Public MAD-related key",
    "B0B1B2B3B4B5": "Common default/test",
    "C0C1C2C3C4C5": "Common default/test",
    "D0D1D2D3D4D5": "Common default/test",
    "AABBCCDDEEFF": "Common default/test",
    "1A982C7E459A": "Common default/test",
    "D3F7D3F7D3F7": "Known public/transit key",
    "5A1B85FCE20A": "Known public/transit key",
    "7C9FB8474242": "NFC Tools public key",
    "123456789ABC": "Common test key",
    "ABCDEF123456": "Common test key",
    "010203040506": "Common test key",
    "112233445566": "Common test key",
    "A0B0C0D0E0F0": "Common test key",
    "A1B1C1D1E1F1": "Common test key",
    "AAAAAAAAAAAA": "Repeated-byte key",
    "BBBBBBBBBBBB": "Repeated-byte key",
    "CCCCCCCCCCCC": "Repeated-byte key",
    "DDDDDDDDDDDD": "Repeated-byte key",
    "EEEEEEEEEEEE": "Repeated-byte key",
    "111111111111": "Repeated-byte key",
    "222222222222": "Repeated-byte key",
    "333333333333": "Repeated-byte key",
    "444444444444": "Repeated-byte key",
    "555555555555": "Repeated-byte key",
    "666666666666": "Repeated-byte key",
    "777777777777": "Repeated-byte key",
    "888888888888": "Repeated-byte key",
    "999999999999": "Repeated-byte key",
}

ACCESS_CONDITION_HINTS = {
    "FF078069": "Transport configuration; GPB 0x69 indicates a non-personalized/non-standard card.",
    "FF0780C1": "MAD1-style directory access profile candidate (GPB 0xC1).",
    "FF0780C2": "MAD2-style directory access profile candidate (GPB 0xC2).",
    "78778800": "Restricted/value-oriented access profile candidate.",
    "00000000": "Blank/invalid access bytes candidate.",
}


def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def safe_json(value: Any) -> str:
    return json.dumps(value if value is not None else {}, ensure_ascii=False, separators=(",", ":"))


def load_json(value: Any, default=None):
    if default is None:
        default = {}
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(str(value)) if value not in (None, "") else default
    except (TypeError, ValueError, json.JSONDecodeError):
        return default


def clean_hex(text: Any) -> str:
    return "".join(ch for ch in str(text or "").upper() if ch in "0123456789ABCDEF")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data or b"").hexdigest()


def byte_entropy(hex_str: str) -> float:
    hx = clean_hex(hex_str)
    if len(hx) < 2 or len(hx) % 2:
        return 0.0
    raw = bytes.fromhex(hx)
    counts = {b: raw.count(b) for b in set(raw)}
    return round(-sum((c / len(raw)) * math.log2(c / len(raw)) for c in counts.values()), 3)


def ascii_preview(hex_str: str) -> str:
    hx = clean_hex(hex_str)
    if len(hx) % 2:
        return ""
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in bytes.fromhex(hx))


def mask_key(key: str) -> str:
    value = clean_hex(key)
    if len(value) <= 8:
        return "•" * len(value)
    return value[:4] + "•" * (len(value) - 8) + value[-4:]


def mask_trailer_block_hex(block_hex: str) -> str:
    """Mask both six-byte keys while preserving the four access/GPB bytes."""
    value = clean_hex(block_hex)
    if len(value) != 32:
        return str(block_hex or "")
    return f"{mask_key(value[:12])}{value[12:20]}{mask_key(value[20:32])}"


def sanitize_report_keys(value, full_keys: bool = False):
    """Return a deep sanitized copy suitable for persisted/shared reports."""
    if full_keys:
        return json.loads(json.dumps(value, ensure_ascii=False))
    if isinstance(value, list):
        return [sanitize_report_keys(item, False) for item in value]
    if not isinstance(value, dict):
        return value
    result = {}
    for key, item in value.items():
        if key.lower() in {"key", "key_a", "key_b"} and isinstance(item, str) and item:
            result[key] = mask_key(item)
        else:
            result[key] = sanitize_report_keys(item, False)
    if result.get("is_trailer") and isinstance(result.get("block_hex"), str):
        result["block_hex"] = mask_trailer_block_hex(result["block_hex"])
        if "ascii" in result:
            result["ascii"] = "[sector trailer; keys masked]"
    return result


def init_card_dump_tables() -> None:
    init_db()


def _looks_textual(data: bytes) -> bool:
    if not data:
        return True
    sample = data[:4096]
    if b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if b in b"\t\r\n" or 32 <= b <= 126)
    return printable / len(sample) > 0.90


def detect_file_type(filename: str = "", data: bytes = b"") -> str:
    name = str(filename or "").lower()
    stripped = (data or b"").lstrip()
    if name.endswith(".json") or stripped.startswith((b"{", b"[")):
        return "json"
    if name.endswith(".mfu"):
        return "mfu_text" if _looks_textual(data) else "mfu_binary"
    if name.endswith((".eml", ".txt", ".hex", ".rfid", ".mct", ".nfc")) and _looks_textual(data):
        return "text"
    if name.endswith((".bin", ".dump", ".mfd", ".mfu")) or not _looks_textual(data):
        return "binary"
    return "text"


def _normalize_unit(value: Any, size: int) -> str | None:
    hx = clean_hex(value)
    expected = size * 2
    if len(hx) == expected:
        return hx
    # Some third-party JSON exporters omit a leading zero on pages.
    if size == 4 and len(hx) == expected - 1:
        return hx.zfill(expected)
    return None


def _sorted_mapping_values(mapping: dict) -> Iterable[Any]:
    def key(value):
        text = str(value)
        return (0, int(text)) if text.isdigit() else (1, text)

    for item_key in sorted(mapping, key=key):
        yield mapping[item_key]


def parse_json_flexible(text: str, filename: str = "") -> tuple[list[str], dict]:
    obj = json.loads(text or "{}")
    meta: dict[str, Any] = {}
    units: list[str] = []
    name = str(filename or "").lower()

    if isinstance(obj, list):
        obj = {"blocks": obj}
    if not isinstance(obj, dict):
        raise ValueError("JSON de dump precisa ser um objeto ou uma lista de blocos.")

    file_label = str(obj.get("FileType") or obj.get("file_type") or "").lower()
    meta.update({k: v for k, v in obj.items() if k not in {"blocks", "pages", "data", "dump", "sectors"}})
    card = obj.get("Card") or obj.get("card") or {}
    if isinstance(card, dict):
        meta["card"] = card
        for source, target in (("UID", "uid"), ("SAK", "sak"), ("ATQA", "atqa"), ("SecurityLevel", "security_level"), ("Version", "version")):
            meta[target] = card.get(source) or card.get(source.lower()) or meta.get(target, "")
    meta["file_type_label"] = file_label
    meta["sector_keys"] = obj.get("SectorKeys") or obj.get("sector_keys") or {}
    meta["applications"] = obj.get("Applications") or obj.get("applications") or []
    meta["files"] = obj.get("Files") or obj.get("files") or []

    explicit_pages = "mfu" in file_label or "ntag" in file_label or "ultralight" in file_label or name.endswith((".mfu", ".nfc")) or "pages" in obj
    explicit_blocks = any(token in file_label for token in ("mfc", "mfp", "classic", "plus"))
    unit_size = 4 if explicit_pages else 16

    source = obj.get("pages") if "pages" in obj else obj.get("blocks")
    if source is None and isinstance(obj.get("sectors"), list):
        source = []
        for sector in obj["sectors"]:
            if isinstance(sector, dict):
                source.extend(sector.get("blocks", []))
    if source is None:
        source = obj.get("data") or obj.get("dump")

    values: Iterable[Any]
    if isinstance(source, dict):
        values = _sorted_mapping_values(source)
    elif isinstance(source, list):
        values = source
    elif source is None:
        values = []
    else:
        hx = clean_hex(source)
        if not explicit_blocks and len(hx) % 8 == 0 and len(hx) % 32 != 0:
            unit_size = 4
        step = unit_size * 2
        values = [hx[i : i + step] for i in range(0, len(hx), step)]

    for item in values:
        if isinstance(item, dict):
            item = item.get("data") or item.get("hex") or item.get("value") or ""
        normalized = _normalize_unit(item, unit_size)
        if normalized:
            units.append(normalized)

    # DESFire can be represented as logical applications/files without a memory dump.
    if not units and any(token in file_label for token in ("desfire", "mfdes")):
        unit_size = 0

    meta["unit_size"] = unit_size
    meta["storage_model"] = "pages" if unit_size == 4 else ("logical" if unit_size == 0 else "blocks")
    return units, meta


def _type2_uid_and_bcc(units: list[str]) -> tuple[str, bool | None]:
    if len(units) < 3 or any(len(clean_hex(u)) != 8 for u in units[:3]):
        return "", None
    raw = b"".join(bytes.fromhex(clean_hex(u)) for u in units[:3])
    uid = bytes([raw[0], raw[1], raw[2], raw[4], raw[5], raw[6], raw[7]])
    bcc0_ok = raw[3] == (0x88 ^ raw[0] ^ raw[1] ^ raw[2])
    bcc1_ok = raw[8] == (raw[4] ^ raw[5] ^ raw[6] ^ raw[7])
    return uid.hex().upper(), bcc0_ok and bcc1_ok


def _mfu_candidate(data: bytes, offset: int, count: int | None = None) -> tuple[list[str], bool | None]:
    body = data[offset:]
    if count is not None:
        body = body[: count * 4]
    body = body[: len(body) - (len(body) % 4)]
    units = [body[i : i + 4].hex().upper() for i in range(0, len(body), 4)]
    return units, _type2_uid_and_bcc(units)[1]


def parse_mfu_binary(data: bytes) -> tuple[list[str], dict]:
    if not data or len(data) < 12:
        raise ValueError("Arquivo MFU binário muito curto.")
    candidates: list[tuple[int, int, list[str], bool | None, dict]] = []

    if len(data) >= MFU_NEW_PREFIX:
        max_page = data[11]
        page_count = max_page + 1
        expected = MFU_NEW_PREFIX + page_count * 4
        if 4 <= page_count <= 256 and len(data) >= expected:
            units, valid = _mfu_candidate(data, MFU_NEW_PREFIX, page_count)
            metadata = {
                "mfu_format": "new-56-byte-prefix",
                "mfu_prefix_length": MFU_NEW_PREFIX,
                "version": data[0:8].hex().upper(),
                "max_page": max_page,
                "signature": data[12:44].hex().upper(),
                "counter_tearing": [data[44 + i * 4 : 48 + i * 4].hex().upper() for i in range(3)],
            }
            candidates.append((3 if valid else 2, MFU_NEW_PREFIX, units, valid, metadata))

    if len(data) > MFU_OLD_PREFIX and (len(data) - MFU_OLD_PREFIX) % 4 == 0:
        units, valid = _mfu_candidate(data, MFU_OLD_PREFIX)
        metadata = {
            "mfu_format": "old-48-byte-prefix",
            "mfu_prefix_length": MFU_OLD_PREFIX,
            "version": data[0:8].hex().upper(),
            "tearing": data[10:13].hex().upper(),
            "pack": data[13:15].hex().upper(),
            "signature": data[16:48].hex().upper(),
        }
        candidates.append((3 if valid else 1, MFU_OLD_PREFIX, units, valid, metadata))

    if len(data) % 4 == 0:
        units, valid = _mfu_candidate(data, 0)
        candidates.append((4 if valid else 0, 0, units, valid, {"mfu_format": "plain-pages", "mfu_prefix_length": 0}))

    if not candidates:
        raise ValueError("Tamanho MFU não corresponde aos formatos de 56, 48 bytes ou páginas puras.")
    candidates.sort(key=lambda item: (item[0], len(item[2])), reverse=True)
    _, _, units, valid, meta = candidates[0]
    meta.update({"unit_size": 4, "storage_model": "pages", "uid_bcc_valid": valid})
    return units, meta


def parse_text_units(text: str, preferred_unit_size: int | None = None) -> tuple[list[str], int]:
    units: list[str] = []
    inferred_sizes: list[int] = []
    for line in str(text or "").splitlines():
        raw = line.strip()
        if not raw or raw.startswith(("#", "+", "//", ";")):
            continue
        # Remove common block/page indexes without consuming their digits as data.
        match = re.match(r"^(?:block|page)?\s*(?:0x)?[0-9a-fA-F]{1,4}\s*[:|]\s*(.*)$", raw, re.IGNORECASE)
        if match:
            raw = match.group(1)
        hx = clean_hex(raw)
        if len(hx) == 8:
            inferred_sizes.append(4)
        elif len(hx) >= 32 and len(hx) % 32 == 0:
            inferred_sizes.append(16)
        else:
            continue

        size = preferred_unit_size or inferred_sizes[-1]
        step = size * 2
        for pos in range(0, len(hx), step):
            chunk = hx[pos : pos + step]
            if len(chunk) == step:
                units.append(chunk)

    if preferred_unit_size:
        return units, preferred_unit_size
    unit_size = 4 if inferred_sizes and inferred_sizes.count(4) > inferred_sizes.count(16) else 16
    # Reparse if mixed lines caused an incompatible initial split.
    reparsed: list[str] = []
    for line in str(text or "").splitlines():
        raw = line.strip()
        match = re.match(r"^(?:block|page)?\s*(?:0x)?[0-9a-fA-F]{1,4}\s*[:|]\s*(.*)$", raw, re.IGNORECASE)
        if match:
            raw = match.group(1)
        hx = clean_hex(raw)
        step = unit_size * 2
        if len(hx) >= step and len(hx) % step == 0:
            reparsed.extend(hx[i : i + step] for i in range(0, len(hx), step))
    return reparsed, unit_size


def parse_dump_units(filename: str, data: bytes) -> tuple[str, list[str], dict]:
    file_type = detect_file_type(filename, data)
    name = str(filename or "").lower()
    meta: dict[str, Any] = {"name_hint": filename or ""}

    if file_type == "json":
        units, parsed_meta = parse_json_flexible(data.decode("utf-8", errors="strict"), filename)
        meta.update(parsed_meta)
    elif file_type == "mfu_binary":
        units, parsed_meta = parse_mfu_binary(data)
        meta.update(parsed_meta)
    elif file_type in {"text", "mfu_text"}:
        preferred = 4 if file_type == "mfu_text" or name.endswith((".mfu", ".nfc")) else None
        units, unit_size = parse_text_units(data.decode("utf-8", errors="replace"), preferred)
        meta.update({"unit_size": unit_size, "storage_model": "pages" if unit_size == 4 else "blocks"})
    else:
        if name.endswith(".mfu"):
            units, parsed_meta = parse_mfu_binary(data)
            meta.update(parsed_meta)
            file_type = "mfu_binary"
        else:
            if len(data) % 16:
                raise ValueError("Dump binário de blocos precisa ter tamanho múltiplo de 16 bytes.")
            units = [data[i : i + 16].hex().upper() for i in range(0, len(data), 16)]
            meta.update({"unit_size": 16, "storage_model": "blocks"})

    if not units and meta.get("storage_model") != "logical":
        raise ValueError("Dump sem blocos/páginas válidos.")
    return file_type, units, meta


def sector_for_block(block_index: int) -> int:
    if block_index < 128:
        return block_index // 4
    return 32 + (block_index - 128) // 16


def block_index_in_sector(block_index: int) -> int:
    if block_index < 128:
        return block_index % 4
    return (block_index - 128) % 16


def is_trailer_block(block_index: int) -> bool:
    return block_index_in_sector(block_index) in ({3} if block_index < 128 else {15})


def sector_for_unit(index: int, unit_size: int) -> int:
    return index // 4 if unit_size == 4 else sector_for_block(index)


def block_index_for_unit(index: int, unit_size: int) -> int:
    return index % 4 if unit_size == 4 else block_index_in_sector(index)


def is_empty_block(block_hex: str) -> bool:
    return clean_hex(block_hex) in {"00" * (len(clean_hex(block_hex)) // 2), "FF" * (len(clean_hex(block_hex)) // 2)}


def infer_card_type(unit_count: int, meta: dict | None = None) -> str:
    meta = meta or {}
    unit_size = int(meta.get("unit_size") or 0)
    label = " ".join(
        str(meta.get(key, "")) for key in ("file_type_label", "card_type", "name_hint")
    ).lower()
    if any(token in label for token in ("desfire", "mfdes")) or meta.get("storage_model") == "logical":
        return "MIFARE DESFire"
    if any(token in label for token in ("mifare plus", "mfp")):
        level = str(meta.get("security_level") or "").upper()
        return f"MIFARE Plus {level}".strip()
    if unit_size == 4:
        return "MIFARE Ultralight / NTAG (Type 2)"
    if unit_size == 16:
        if unit_count == 20:
            return "MIFARE Classic Mini"
        if unit_count == MIFARE_1K_BLOCKS:
            return "MIFARE Classic 1K"
        if unit_count == MIFARE_2K_BLOCKS:
            return "MIFARE Classic 2K"
        if unit_count == MIFARE_4K_BLOCKS:
            return "MIFARE Classic 4K"
        if "mfc" in label or "classic" in label:
            return "MIFARE Classic (partial/non-standard dump)"
    return "Unknown RFID/NFC dump"



def _xor_bytes(data: bytes) -> int:
    value = 0
    for byte in data:
        value ^= byte
    return value


def extract_uid_sak_atqa(units: list[str], meta: dict | None = None) -> tuple[str, str, str, dict]:
    meta = meta or {}
    uid = clean_hex(meta.get("uid") or (meta.get("card") or {}).get("UID"))
    sak = clean_hex(meta.get("sak") or (meta.get("card") or {}).get("SAK"))
    atqa = clean_hex(meta.get("atqa") or (meta.get("card") or {}).get("ATQA"))
    evidence: dict[str, Any] = {"uid_source": "metadata" if uid else "none", "uid_bcc_valid": None}
    unit_size = int(meta.get("unit_size") or 0)

    if not uid and unit_size == 4:
        uid, valid = _type2_uid_and_bcc(units)
        evidence.update({"uid_source": "type2_manufacturer_pages", "uid_bcc_valid": valid})
    elif not uid and unit_size == 16 and units:
        raw = bytes.fromhex(clean_hex(units[0]))
        candidates = []
        for length in (4, 7, 10):
            if len(raw) > length:
                candidate = raw[:length]
                candidates.append((length, candidate, raw[length] == _xor_bytes(candidate)))
        selected = next((item for item in candidates if item[2]), candidates[0] if candidates else None)
        if selected:
            length, candidate, valid = selected
            uid = candidate.hex().upper()
            evidence.update({
                "uid_source": "classic_manufacturer_block",
                "uid_length_bytes": length,
                "uid_bcc_valid": valid,
                "uid_bcc_method": "linear manufacturer-block BCC",
            })
    return uid, sak, atqa, evidence


def detect_value_block(block_hex: str) -> dict | None:
    hx = clean_hex(block_hex)
    if len(hx) != 32:
        return None
    raw = bytes.fromhex(hx)
    value = raw[0:4]
    inverted = raw[4:8]
    repeated = raw[8:12]
    address = raw[12]
    if repeated != value or any((value[i] ^ inverted[i]) != 0xFF for i in range(4)):
        return None
    if raw[13] != (address ^ 0xFF) or raw[14] != address or raw[15] != (address ^ 0xFF):
        return None
    signed_value = int.from_bytes(value, "little", signed=True)
    return {"value": signed_value, "address": address, "valid": True}


def crc8_mad(data: bytes) -> int:
    crc = 0xC7
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1D) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def _parse_aids(payload: bytes, start_sector: int) -> list[dict]:
    aids = []
    for offset in range(0, len(payload), 2):
        if offset + 1 >= len(payload):
            break
        function_cluster = payload[offset]
        application_code = payload[offset + 1]
        sector = start_sector + offset // 2
        aids.append({
            "sector": sector,
            "aid": f"{function_cluster:02X}{application_code:02X}",
            "function_cluster": f"{function_cluster:02X}",
            "application_code": f"{application_code:02X}",
            "administration": function_cluster == 0,
        })
    return aids


def detect_mad(units: list[str], analysis_blocks: list[dict]) -> list[dict]:
    if len(units) < 4:
        return []
    trailer = next((b for b in analysis_blocks if b["absolute_block"] == 3 and b["is_trailer"]), None)
    if not trailer:
        return []
    gpb = int(trailer.get("access_bits", "00000000")[-2:] or "00", 16)
    directory_available = bool(gpb & 0x80)
    multi_application = bool(gpb & 0x40)
    version_code = gpb & 0x03
    version = {1: 1, 2: 2}.get(version_code)
    key_valid = trailer.get("key_a") == "A0A1A2A3A4A5"
    if not directory_available or version not in {1, 2} or not key_valid:
        return []

    block1 = bytes.fromhex(clean_hex(units[1]))
    block2 = bytes.fromhex(clean_hex(units[2]))
    expected_crc = block1[0]
    calculated_crc = crc8_mad(block1[1:] + block2)
    aids = _parse_aids(block1[2:] + block2, 1)
    result = [{
        "type": "MAD",
        "version": version,
        "gpb": f"{gpb:02X}",
        "directory_available": directory_available,
        "multi_application": multi_application,
        "key_a_valid": key_valid,
        "crc_expected": f"{expected_crc:02X}",
        "crc_calculated": f"{calculated_crc:02X}",
        "crc_valid": expected_crc == calculated_crc,
        "aids": aids,
    }]

    # MAD2 extended directory in sector 0x10 (block 128 onwards on 4K/Plus 4K).
    if version == 2 and len(units) >= 132:
        ext0, ext1, ext2 = (bytes.fromhex(clean_hex(units[i])) for i in (128, 129, 130))
        ext_trailer = next((b for b in analysis_blocks if b["absolute_block"] == 143 and b["is_trailer"]), None)
        if ext_trailer and ext_trailer.get("key_a") == "A0A1A2A3A4A5":
            expected = ext0[0]
            calculated = crc8_mad(ext0[1:] + ext1 + ext2)
            result.append({
                "type": "MAD2_EXTENDED",
                "crc_expected": f"{expected:02X}",
                "crc_calculated": f"{calculated:02X}",
                "crc_valid": expected == calculated,
                "aids": _parse_aids(ext0[2:] + ext1 + ext2, 17),
            })
    return result


def _sector_key_from_metadata(meta: dict, sector: int) -> dict:
    keys = meta.get("sector_keys") or {}
    value = keys.get(str(sector)) or keys.get(sector) or {}
    return value if isinstance(value, dict) else {}


def analyze_blocks(units: list[str], meta: dict | None = None) -> tuple[list[dict], dict]:
    meta = meta or {}
    unit_size = int(meta.get("unit_size") or 0)
    label = " ".join(str(meta.get(key, "")) for key in ("file_type_label", "card_type", "name_hint")).lower()
    mifare_plus = "mifare plus" in label or "mfp" in label
    security_level = str(meta.get("security_level") or "").upper()
    results: list[dict] = []
    stats: dict[str, Any] = {
        "empty_blocks": 0,
        "trailer_blocks": 0,
        "default_key_blocks": 0,  # compatibility: sectors with at least one public/default key
        "default_key_sectors": 0,
        "default_key_a_count": 0,
        "default_key_b_count": 0,
        "default_key_both_count": 0,
        "default_keys": [],
        "known_sector_keys": 0,
        "known_access_conditions": 0,
        "invalid_access_conditions": 0,
        "value_blocks": 0,
        "ascii_blocks": 0,
        "entropy_avg": 0.0,
        "sector_profiles": {},
        "unit_size": unit_size,
        "storage_model": meta.get("storage_model", "blocks"),
        "protocol_model": "mifare_plus" if mifare_plus else ("type2" if unit_size == 4 else "mifare_classic"),
        "security_level": security_level,
    }

    default_sectors: set[int] = set()
    entropies_by_sector: dict[int, list[float]] = {}

    for index, unit in enumerate(units):
        sector = sector_for_unit(index, unit_size)
        block_index = block_index_for_unit(index, unit_size)
        trailer = unit_size == 16 and is_trailer_block(index)
        empty = is_empty_block(unit)
        entropy = byte_entropy(unit)
        preview = ascii_preview(unit)
        has_ascii = sum(ch != "." for ch in preview) >= max(2, len(preview) // 3)
        value_block = detect_value_block(unit) if unit_size == 16 and not trailer else None
        annotations: list[Any] = []
        key_a = access_bits = key_b = ""
        decoded_access: dict = {}
        default_labels: list[dict] = []

        if empty:
            stats["empty_blocks"] += 1
            annotations.append("EMPTY_BLOCK")
        if has_ascii:
            stats["ascii_blocks"] += 1
            annotations.append("ASCII_VISIBLE")
        if value_block:
            stats["value_blocks"] += 1
            annotations.append({"VALUE_BLOCK": value_block})

        if unit_size == 4:
            if index == 0:
                annotations.append("MANUFACTURER_PAGE")
            elif index == 2:
                annotations.append("INTERNAL_AND_LOCK_BYTES")
            elif index == 3:
                annotations.append("CAPABILITY_CONTAINER")
        elif trailer:
            stats["trailer_blocks"] += 1
            metadata_keys = _sector_key_from_metadata(meta, sector)
            decoded = decode_sector_trailer(unit)
            # MIFARE Plus dumps commonly contain inaccessible/placeholder trailer bytes.
            # Never interpret those bytes as recovered AES/sector keys. Keys must come
            # from explicit metadata; raw Classic-compatible access bytes are used only
            # for SL0/SL1 or ordinary MIFARE Classic dumps.
            if mifare_plus:
                key_a = clean_hex(metadata_keys.get("KeyA") or metadata_keys.get("key_a"))
                key_b = clean_hex(metadata_keys.get("KeyB") or metadata_keys.get("key_b"))
                raw_access = decoded.get("access_bits") if security_level in {"SL0", "SL1"} else ""
                access_bits = clean_hex(metadata_keys.get("AccessConditions") or metadata_keys.get("access_bits") or raw_access)[:8]
            else:
                key_a = clean_hex(metadata_keys.get("KeyA") or metadata_keys.get("key_a") or decoded.get("key_a"))
                key_b = clean_hex(metadata_keys.get("KeyB") or metadata_keys.get("key_b") or decoded.get("key_b"))
                access_bits = clean_hex(metadata_keys.get("AccessConditions") or metadata_keys.get("access_bits") or decoded.get("access_bits"))[:8]
            decoded_access = decode_access_conditions(access_bits) if access_bits else {}
            if key_a or key_b:
                stats["known_sector_keys"] += 1
            if access_bits:
                if decoded_access.get("valid"):
                    stats["known_access_conditions"] += 1
                else:
                    stats["invalid_access_conditions"] += 1
                annotations.append({"DECODED_ACCESS": decoded_access})
                if access_bits in ACCESS_CONDITION_HINTS:
                    annotations.append("ACCESS_HINT:" + ACCESS_CONDITION_HINTS[access_bits])

            a_default = key_a in DEFAULT_KEYS
            b_default = key_b in DEFAULT_KEYS
            if a_default:
                stats["default_key_a_count"] += 1
                default_labels.append({"key_type": "A", "key": key_a, "label": DEFAULT_KEYS[key_a]})
            if b_default:
                stats["default_key_b_count"] += 1
                default_labels.append({"key_type": "B", "key": key_b, "label": DEFAULT_KEYS[key_b]})
            if a_default and b_default:
                stats["default_key_both_count"] += 1
            if a_default or b_default:
                default_sectors.add(sector)
                stats["default_keys"].extend({"sector": sector, "block": index, **item} for item in default_labels)
                annotations.extend(f"DEFAULT_KEY_{item['key_type']}:{item['label']}" for item in default_labels)

        entropies_by_sector.setdefault(sector, []).append(entropy)
        results.append({
            "sector": sector,
            "block_index": block_index,
            "absolute_block": index,
            "block_hex": clean_hex(unit),
            "ascii": preview,
            "entropy": entropy,
            "is_trailer": trailer,
            "key_a": key_a,
            "access_bits": access_bits,
            "key_b": key_b,
            "decoded_access": decoded_access,
            "is_empty": empty,
            "is_value_block": bool(value_block),
            "value_block": value_block,
            "has_ascii": has_ascii,
            "has_default_key": bool(default_labels),
            "default_key_labels": default_labels,
            "annotations": annotations,
        })

    stats["default_key_sectors"] = len(default_sectors)
    stats["default_key_blocks"] = len(default_sectors)
    stats["entropy_avg"] = round(statistics.mean([r["entropy"] for r in results]), 3) if results else 0.0
    stats["sector_count"] = len(entropies_by_sector)

    for sector, entropies in entropies_by_sector.items():
        rows = [r for r in results if r["sector"] == sector]
        trailer = next((r for r in rows if r["is_trailer"]), None)
        data_rows = [r for r in rows if not r["is_trailer"]]
        stats["sector_profiles"][str(sector)] = {
            "data_blocks": len(data_rows),
            "empty_data_blocks": sum(r["is_empty"] for r in data_rows),
            "has_default_key": bool(trailer and trailer["has_default_key"]),
            "key_a": trailer["key_a"] if trailer else "",
            "key_b": trailer["key_b"] if trailer else "",
            "access_bits": trailer["access_bits"] if trailer else "",
            "access_decoded": trailer["decoded_access"] if trailer else {},
            "entropy_avg": round(statistics.mean(entropies), 3),
        }
    return results, stats


def build_static_security_evidence(card_type: str, stats: dict, id_evidence: dict, mad: list[dict], meta: dict) -> dict:
    evidence = {
        "known_or_default_keys": stats.get("default_key_sectors", 0),
        "static_data_visible_blocks": stats.get("ascii_blocks", 0),
        "empty_memory_units": stats.get("empty_blocks", 0),
        "uid_integrity": "valid" if id_evidence.get("uid_bcc_valid") is True else ("invalid" if id_evidence.get("uid_bcc_valid") is False else "not_verified"),
        "magic_card_evidence": [],
        "uid_mutability_proven": False,
        "application_clone_feasibility": "not_determined_from_static_dump",
    }
    explicit_magic = meta.get("magic") or meta.get("uid_changeable") or meta.get("magic_type")
    if explicit_magic:
        evidence["magic_card_evidence"].append({"source": "metadata", "value": explicit_magic})
    evidence["uid_mutability_proven"] = bool(evidence["magic_card_evidence"])

    score = 0
    reasons = []
    if stats.get("default_key_sectors"):
        score += min(40, stats["default_key_sectors"] * 5)
        reasons.append("Public/default keys detected in one or more sectors")
    if stats.get("ascii_blocks"):
        score += min(15, stats["ascii_blocks"])
        reasons.append("Static plaintext-like content is visible")
    if id_evidence.get("uid_bcc_valid") is False:
        score += 10
        reasons.append("UID/BCC integrity check failed")
    if evidence["magic_card_evidence"]:
        score += 25
        reasons.append("Explicit magic/UID-changeable evidence supplied by metadata")
    if "Classic" in card_type:
        reasons.append("MIFARE Classic uses legacy Crypto1, but this alone does not prove application cloning")
    evidence.update({
        "score": min(100, score),
        "status": "STATIC_WEAKNESS_INDICATORS" if score else "NO_STATIC_WEAKNESS_CONFIRMED",
        "reasons": reasons,
        "caveat": "A static dump cannot prove writable UID, reader behavior, backend checks, or full credential cloning.",
    })
    return evidence


def calculate_risk(card_type: str, stats: dict, id_evidence: dict, mad: list[dict], evidence: dict) -> tuple[str, int, list[str]]:
    score = 0
    reasons: list[str] = []
    default_sectors = stats.get("default_key_sectors", 0)
    if default_sectors:
        score += min(45, 10 + default_sectors * 4)
        reasons.append(f"{default_sectors} setor(es) usam ao menos uma chave pública/default")
    if stats.get("invalid_access_conditions"):
        score += min(20, stats["invalid_access_conditions"] * 5)
        reasons.append("Access bits inválidos ou inconsistentes")
    if id_evidence.get("uid_bcc_valid") is False:
        score += 10
        reasons.append("BCC do UID inválido")
    if any(item.get("crc_valid") is False for item in mad):
        score += 10
        reasons.append("Diretório MAD presente com CRC inválido")
    if evidence.get("magic_card_evidence"):
        score += 20
        reasons.append("Metadado explícito indica cartão magic/UID-changeable")
    if "Unknown" in card_type:
        score += 5
        reasons.append("Tipo não identificado com confiança")
    if stats.get("ascii_blocks", 0) >= 3:
        score += 5
        reasons.append("Conteúdo textual estático visível")
    score = min(100, score)
    level = "CRITICAL" if score >= 80 else "HIGH" if score >= 55 else "MEDIUM" if score >= 25 else "LOW"
    return level, score, reasons


def parse_dump_content(filename: str, data: bytes) -> dict:
    file_type, units, meta = parse_dump_units(filename, data)
    card_type = infer_card_type(len(units), meta)
    uid, sak, atqa, id_evidence = extract_uid_sak_atqa(units, meta)
    block_analysis, stats = analyze_blocks(units, meta)
    mad = detect_mad(units, block_analysis) if int(meta.get("unit_size") or 0) == 16 else []
    ndef = decode_ndef_from_units(units) if int(meta.get("unit_size") or 0) == 4 else {"found": False, "tlvs": [], "records": []}
    security_evidence = build_static_security_evidence(card_type, stats, id_evidence, mad, meta)
    risk_level, risk_score, risk_reasons = calculate_risk(card_type, stats, id_evidence, mad, security_evidence)
    return {
        "file_type": file_type,
        "blocks": units,
        "card_type": card_type,
        "uid": uid,
        "sak": sak,
        "atqa": atqa,
        "block_count": len(units),
        "sector_count": stats.get("sector_count", 0),
        "block_analysis": block_analysis,
        "stats": stats,
        "mad_aid": mad,
        "ndef": ndef,
        "identity_evidence": id_evidence,
        "magic_findings": security_evidence.get("magic_card_evidence", []),
        "security_evidence": security_evidence,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "risk_reasons": risk_reasons,
        "metadata": meta,
    }


def save_uploaded_dump(filename: str, data: bytes) -> Path:
    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", str(filename or "dump"))[:100] or "dump"
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    path = DUMP_DIR / f"{stamp}_{uuid.uuid4().hex[:8]}_{safe_name}"
    path.write_bytes(data or b"")
    return path


def build_recommendations(analysis: dict) -> list[str]:
    rec: list[str] = []
    stats = analysis["stats"]
    if stats.get("default_key_sectors"):
        rec.append("Substituir chaves públicas/default por chaves exclusivas e diversificadas por aplicação/cartão.")
    if stats.get("invalid_access_conditions"):
        rec.append("Revisar Access Bits; uma inversão inválida pode tornar o setor inacessível ou diferente do esperado.")
    if any(item.get("crc_valid") is False for item in analysis.get("mad_aid", [])):
        rec.append("Regerar ou corrigir o CRC do MIFARE Application Directory antes de confiar nos AIDs.")
    if analysis.get("identity_evidence", {}).get("uid_bcc_valid") is False:
        rec.append("Confirmar o bloco fabricante com `hf 14a info`; o BCC do UID não é consistente.")
    if not analysis.get("uid"):
        rec.append("Anexar saída de identificação do leitor para enriquecer UID, SAK, ATQA e versão.")
    rec.append("Não inferir clonabilidade apenas pelo dump; validar leitor, backend, autenticação e mutabilidade do UID separadamente.")
    return rec


def generate_forensic_report(dump_id: int, analysis: dict, dump_name: str) -> tuple[dict, str]:
    full_keys = os.environ.get("UTAMO_EXPORT_FULL_KEYS", "").lower() in {"1", "true", "yes", "on"}
    default_keys = []
    for entry in analysis["stats"].get("default_keys", []):
        entry = dict(entry)
        if not full_keys:
            entry["key"] = mask_key(entry.get("key", ""))
        default_keys.append(entry)
    report = {
        "schema": "utamo-rfid-report-v3",
        "dump_id": dump_id,
        "dump_name": dump_name,
        "generated_at": now(),
        "summary": {
            "card_type": analysis["card_type"],
            "uid": analysis["uid"],
            "sak": analysis["sak"],
            "atqa": analysis["atqa"],
            "file_type": analysis["file_type"],
            "block_count": analysis["block_count"],
            "sector_count": analysis["sector_count"],
            "risk_level": analysis["risk_level"],
            "risk_score": analysis["risk_score"],
            "security_evidence": analysis["security_evidence"],
            "storage_model": analysis["stats"].get("storage_model"),
            "unit_size": analysis["stats"].get("unit_size"),
        },
        "identity_evidence": analysis.get("identity_evidence", {}),
        "risk_reasons": analysis["risk_reasons"],
        "mad_aid": analysis["mad_aid"],
        "ndef": analysis.get("ndef", {"found": False, "tlvs": [], "records": []}),
        "security_evidence": analysis["security_evidence"],
        "magic_findings": analysis.get("magic_findings", []),
        "statistics": {
            **{k: v for k, v in analysis["stats"].items() if k not in {"default_keys", "sector_profiles"}},
            "default_keys": default_keys,
            "sector_profiles": analysis["stats"].get("sector_profiles", {}),
        },
        "recommendations": build_recommendations(analysis),
        "blocks": analysis["block_analysis"],
        "export_policy": {"keys_masked": not full_keys},
    }
    report = sanitize_report_keys(report, full_keys=full_keys)
    report_path = REPORT_DIR / f"rfid_report_{dump_id}_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    with transaction() as conn:
        conn.execute(
            "INSERT INTO rfid_card_reports(dump_id,report_path,report_json,created_at) VALUES (?,?,?,?)",
            (dump_id, str(report_path), json.dumps(report, ensure_ascii=False), now()),
        )
    return report, str(report_path)


def find_duplicate_by_sha256(digest: str):
    init_db()
    conn = get_conn()
    try:
        return conn.execute("SELECT id FROM rfid_card_dumps WHERE sha256=? ORDER BY id LIMIT 1", (digest,)).fetchone()
    finally:
        conn.close()


def update_card_inventory(uid: str, card_type: str, risk_level: str) -> None:
    if not uid:
        return
    with transaction() as conn:
        conn.execute(
            """
            INSERT INTO card_inventory(uid,card_type,first_seen,last_seen,dump_count,risk_level)
            VALUES (?,?,?,?,1,?)
            ON CONFLICT(uid) DO UPDATE SET card_type=excluded.card_type,last_seen=excluded.last_seen,
                dump_count=card_inventory.dump_count+1,risk_level=excluded.risk_level
            """,
            (uid, card_type, now(), now(), risk_level),
        )


def ingest_card_dump(filename: str, data: bytes, dump_name: str | None = None) -> dict:
    init_db()
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Conteúdo do dump precisa ser binário.")
    data = bytes(data)
    if not data:
        raise ValueError("Arquivo vazio.")
    analysis = parse_dump_content(filename, data)
    digest = sha256_bytes(data)
    duplicate = find_duplicate_by_sha256(digest)
    path = save_uploaded_dump(filename, data)
    metadata = dict(analysis["metadata"])
    metadata.update({
        "identity_evidence": analysis.get("identity_evidence", {}),
        "analysis_schema": "utamo-rfid-analysis-v3",
        "upstream": "RfidResearchGroup/proxmark3",
        "upstream_commit": os.environ.get("UTAMO_PM3_UPSTREAM_COMMIT", "master"),
    })
    with transaction() as conn:
        cur = conn.execute(
            """
            INSERT INTO rfid_card_dumps(
                dump_name,file_name,file_type,file_path,sha256,size_bytes,card_type,uid,sak,atqa,
                block_count,sector_count,risk_level,summary,metadata,duplicate_of,created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                dump_name or filename, filename, analysis["file_type"], str(path), digest, len(data),
                analysis["card_type"], analysis["uid"], analysis["sak"], analysis["atqa"],
                analysis["block_count"], analysis["sector_count"], analysis["risk_level"],
                "; ".join(analysis["risk_reasons"]) or "Nenhum indicador crítico confirmado.",
                json.dumps(metadata, ensure_ascii=False), duplicate[0] if duplicate else None, now(),
            ),
        )
        dump_id = int(cur.lastrowid)
        for block in analysis["block_analysis"]:
            conn.execute(
                """
                INSERT INTO rfid_card_blocks(
                    dump_id,sector,block_index,absolute_block,block_hex,is_trailer,key_a,access_bits,key_b,
                    is_empty,has_default_key,annotations,created_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    dump_id, block["sector"], block["block_index"], block["absolute_block"], block["block_hex"],
                    int(block["is_trailer"]), block["key_a"], block["access_bits"], block["key_b"],
                    int(block["is_empty"]), int(block["has_default_key"]), json.dumps(block["annotations"], ensure_ascii=False), now(),
                ),
            )
    report, report_path = generate_forensic_report(dump_id, analysis, dump_name or filename)
    update_card_inventory(analysis["uid"], analysis["card_type"], analysis["risk_level"])
    return {
        "dump_id": dump_id,
        "duplicate_of": duplicate[0] if duplicate else None,
        "report_path": report_path,
        "analysis": {
            "file_type": analysis["file_type"],
            "card_type": analysis["card_type"],
            "uid": analysis["uid"],
            "sak": analysis["sak"],
            "atqa": analysis["atqa"],
            "block_count": analysis["block_count"],
            "sector_count": analysis["sector_count"],
            "risk_level": analysis["risk_level"],
            "risk_score": analysis["risk_score"],
            "risk_reasons": analysis["risk_reasons"],
            "security_evidence": analysis["security_evidence"],
        },
        "report": report,
    }


def analyze_text_payload(name: str, text: str) -> dict:
    return ingest_card_dump(name or "manual_dump.txt", str(text or "").encode("utf-8"), name or "Manual dump")


def list_card_dumps(limit: int = 100):
    init_db()
    conn = get_conn()
    try:
        return conn.execute(
            """
            SELECT id,dump_name,file_name,file_type,card_type,uid,block_count,sector_count,risk_level,summary,created_at
            FROM rfid_card_dumps ORDER BY id DESC LIMIT ?
            """,
            (max(1, min(1000, int(limit or 100))),),
        ).fetchall()
    finally:
        conn.close()


def get_card_dump(dump_id: int):
    init_db()
    conn = get_conn()
    try:
        return conn.execute(
            """SELECT id,dump_name,file_name,file_type,file_path,sha256,size_bytes,card_type,uid,sak,atqa,
                      block_count,sector_count,risk_level,summary,metadata,duplicate_of,created_at
               FROM rfid_card_dumps WHERE id=?""",
            (int(dump_id),),
        ).fetchone()
    finally:
        conn.close()


def list_card_blocks(dump_id: int, limit: int = 1000):
    init_db()
    conn = get_conn()
    try:
        return conn.execute(
            """SELECT sector,block_index,absolute_block,block_hex,is_trailer,key_a,access_bits,key_b,
                      is_empty,has_default_key,annotations
               FROM rfid_card_blocks WHERE dump_id=? ORDER BY absolute_block LIMIT ?""",
            (int(dump_id), max(1, min(5000, int(limit or 1000)))),
        ).fetchall()
    finally:
        conn.close()


def get_latest_report(dump_id: int) -> dict:
    init_db()
    conn = get_conn()
    try:
        row = conn.execute("SELECT report_json FROM rfid_card_reports WHERE dump_id=? ORDER BY id DESC LIMIT 1", (int(dump_id),)).fetchone()
        return load_json(row[0], {}) if row else {}
    finally:
        conn.close()


def compare_dumps(dump_a: int, dump_b: int) -> dict:
    if not get_card_dump(dump_a) or not get_card_dump(dump_b):
        raise ValueError("Um ou ambos os dumps não existem.")
    rows_a = list_card_blocks(dump_a, 5000)
    rows_b = list_card_blocks(dump_b, 5000)
    map_a = {row[2]: row for row in rows_a}
    map_b = {row[2]: row for row in rows_b}
    indexes = sorted(set(map_a) | set(map_b))
    differences = []
    for index in indexes:
        row_a, row_b = map_a.get(index), map_b.get(index)
        hex_a = row_a[3] if row_a else None
        hex_b = row_b[3] if row_b else None
        if hex_a == hex_b:
            continue
        reference = row_a or row_b
        differences.append({
            "absolute_block": index,
            "sector": reference[0] if reference else sector_for_block(index),
            "block": reference[1] if reference else block_index_in_sector(index),
            "is_trailer": bool(reference[4]) if reference else is_trailer_block(index),
            "a": hex_a,
            "b": hex_b,
        })
    comparable = max(1, len(indexes))
    similarity = round(100 * (comparable - len(differences)) / comparable, 2)
    trailer_changes = sum(item["is_trailer"] for item in differences)
    report = {
        "dump_a": int(dump_a),
        "dump_b": int(dump_b),
        "similarity": similarity,
        "changed_blocks": len(differences),
        "trailer_changes": trailer_changes,
        "differences": differences,
        "changes": differences,
        "static_similarity_score": round(similarity),
        "comparison_status": "STATIC_SIMILARITY_ONLY",
        "interpretation": "Similaridade estática de bytes; o resultado não comprova clonagem de credencial.",
    }
    with transaction() as conn:
        conn.execute(
            """INSERT INTO rfid_dump_comparisons(dump_a,dump_b,similarity,changed_blocks,static_similarity_score,comparison_status,report_json,created_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (int(dump_a), int(dump_b), similarity, len(differences), round(similarity), "STATIC_SIMILARITY_ONLY", json.dumps(report, ensure_ascii=False), now()),
        )
    return report


def list_comparisons(limit: int = 100):
    init_db()
    conn = get_conn()
    try:
        return conn.execute(
            "SELECT id,dump_a,dump_b,similarity,changed_blocks,static_similarity_score,comparison_status,created_at FROM rfid_dump_comparisons ORDER BY id DESC LIMIT ?",
            (max(1, min(1000, int(limit or 100))),),
        ).fetchall()
    finally:
        conn.close()


def record_pm3_event(source: str, event_type: str, uid: str = "", protocol: str = "", severity: str = "INFO", summary: str = "", payload=None):
    with transaction() as conn:
        conn.execute(
            "INSERT INTO rfid_pm3_events(source,event_type,uid,protocol,severity,summary,payload,created_at) VALUES (?,?,?,?,?,?,?,?)",
            (source, event_type, uid, protocol, severity, summary, json.dumps(payload or {}, ensure_ascii=False), now()),
        )


def _first_match(patterns: Iterable[str], text: str) -> str:
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return clean_hex(match.group(1))
    return ""


def _version_line(raw: str, labels: tuple[str, ...]) -> str:
    for line in raw.splitlines():
        clean = line.strip().lstrip("[#*+ -]").strip()
        lower = clean.lower()
        if any(label in lower for label in labels):
            return clean[:500]
    return ""


def record_pm3_runtime_version(client_version: str = "", firmware_version: str = "", bootrom_version: str = "", source_command: str = "", raw_excerpt: str = "") -> None:
    if not any((client_version, firmware_version, bootrom_version)):
        return
    with transaction() as conn:
        conn.execute(
            "INSERT INTO proxmark_runtime_versions(client_version,firmware_version,bootrom_version,source_command,raw_excerpt,observed_at) VALUES (?,?,?,?,?,?)",
            (client_version, firmware_version, bootrom_version, source_command, raw_excerpt[:4000], now()),
        )


def parse_pm3_output(text: str, *, source: str = "proxmark_output") -> dict:
    raw = str(text or "")[:100_000]
    low = raw.lower()
    uid = _first_match((r"\buid\s*[:=]\s*([0-9a-f][0-9a-f :.-]{5,30})", r"\bcsn\s*[:=]\s*([0-9a-f][0-9a-f :.-]{5,30})"), raw)
    sak = _first_match((r"\bsak\s*[:=]\s*([0-9a-f]{1,4})",), raw)
    atqa = _first_match((r"\batqa\s*[:=]\s*([0-9a-f ]{2,8})",), raw)
    protocol = "RFID"
    event_type = "PM3_OUTPUT"
    severity = "INFO"
    rules = [
        (("mifare plus", "hf mfp", " sl3", " sl1"), "MIFARE Plus", "MFP_DETECTED"),
        (("mifare classic", "hf mf"), "MIFARE Classic", "MFC_DETECTED"),
        (("ultralight", "ntag", "hf mfu"), "MIFARE Ultralight / NTAG", "MFU_DETECTED"),
        (("desfire", "hf mfdes"), "MIFARE DESFire", "DESFIRE_DETECTED"),
        (("iso14443-a", "hf 14a"), "ISO14443-A", "HF_14A_DETECTED"),
        (("iso15693", "hf 15"), "ISO15693", "HF_15_DETECTED"),
    ]
    for needles, detected_protocol, detected_event in rules:
        if any(needle in low for needle in needles):
            protocol, event_type = detected_protocol, detected_event
            break
    findings: list[dict] = []
    if any(word in low for word in ("magic", "gen1a", "uid changeable", "backdoor")):
        findings.append({"type": "MAGIC_CARD_EXPLICIT_OUTPUT", "severity": "HIGH"})
        severity = "HIGH"
    if any(word in low for word in ("default key", "key found", "found key")):
        findings.append({"type": "PUBLIC_OR_RECOVERED_KEY_OUTPUT", "severity": "MEDIUM"})
        severity = "MEDIUM" if severity == "INFO" else severity
    suggestions = suggest_protocol_from_text(raw)
    versions = {
        "client": _version_line(raw, ("client:", "client version", "proxmark3 client")),
        "firmware": _version_line(raw, ("device:", "firmware", "os:", "armsrc")),
        "bootrom": _version_line(raw, ("bootrom", "boot rom")),
    }
    if any(versions.values()):
        record_pm3_runtime_version(versions["client"], versions["firmware"], versions["bootrom"], "parsed-output", raw)
    summary = f"{event_type} | protocol={protocol} | uid={uid or '--'}"
    payload = {"raw": raw[:8000], "findings": findings, "sak": sak, "atqa": atqa, "suggestions": suggestions[:5], "versions": versions}
    record_pm3_event(source, event_type, uid, protocol, severity, summary, payload)
    return {"event_type": event_type, "uid": uid, "sak": sak, "atqa": atqa, "protocol": protocol, "severity": severity, "findings": findings, "suggestions": suggestions[:5], "versions": versions}


def list_pm3_events(limit: int = 100):
    init_db()
    conn = get_conn()
    try:
        return conn.execute(
            "SELECT id,source,event_type,uid,protocol,severity,summary,created_at FROM rfid_pm3_events ORDER BY id DESC LIMIT ?",
            (max(1, min(1000, int(limit or 100))),),
        ).fetchall()
    finally:
        conn.close()


def _block_visual_object(row) -> dict:
    annotations = load_json(row[10], [])
    if not isinstance(annotations, list):
        annotations = [annotations]
    decoded_access = next((item.get("DECODED_ACCESS") for item in annotations if isinstance(item, dict) and "DECODED_ACCESS" in item), {})
    annotation_preview = []
    for item in annotations:
        if isinstance(item, dict):
            annotation_preview.extend(item.keys())
        else:
            annotation_preview.append(str(item))
    key_a, access_bits, key_b = row[5] or "", row[6] or "", row[7] or ""
    labels = []
    if key_a in DEFAULT_KEYS:
        labels.append({"key_type": "A", "key": key_a, "label": DEFAULT_KEYS[key_a]})
    if key_b in DEFAULT_KEYS:
        labels.append({"key_type": "B", "key": key_b, "label": DEFAULT_KEYS[key_b]})
    return {
        "sector": row[0], "block_index": row[1], "absolute_block": row[2], "block_hex": row[3],
        "ascii": ascii_preview(row[3]), "entropy": byte_entropy(row[3]), "is_trailer": bool(row[4]),
        "key_a": key_a, "access_bits": access_bits, "key_b": key_b, "is_empty": bool(row[8]),
        "has_default_key": bool(row[9]), "annotations": annotations, "annotation_preview": annotation_preview[:5],
        "default_key_labels": labels, "access_hint": ACCESS_CONDITION_HINTS.get(access_bits, ""),
        "decoded_access": decoded_access or (decode_access_conditions(access_bits) if access_bits else {}),
        "is_value_block": any(isinstance(item, dict) and "VALUE_BLOCK" in item for item in annotations),
        "has_ascii": "ASCII_VISIBLE" in annotations,
    }


def _group_blocks_by_sector(blocks: list[dict]) -> list[dict]:
    sectors: dict[int, dict] = {}
    for block in blocks:
        sector = sectors.setdefault(block["sector"], {
            "sector": block["sector"], "blocks": [], "trailer": None, "data_blocks": 0,
            "empty_blocks": 0, "ascii_blocks": 0, "value_blocks": 0, "default_keys": [],
            "access_bits": "", "access_hint": "", "risk_flags": [], "entropy_avg": 0,
        })
        sector["blocks"].append(block)
        if block["is_trailer"]:
            sector["trailer"] = block
            sector["access_bits"] = block["access_bits"]
            sector["access_hint"] = block["access_hint"]
            sector["default_keys"].extend(block["default_key_labels"])
        else:
            sector["data_blocks"] += 1
        sector["empty_blocks"] += int(block["is_empty"])
        sector["ascii_blocks"] += int(block["has_ascii"])
        sector["value_blocks"] += int(block["is_value_block"])
        if block["has_default_key"]:
            sector["risk_flags"].append("DEFAULT_KEY")
        if block["is_value_block"]:
            sector["risk_flags"].append("VALUE_BLOCK")
    for sector in sectors.values():
        sector["blocks"].sort(key=lambda item: item["absolute_block"])
        sector["entropy_avg"] = round(statistics.mean([b["entropy"] for b in sector["blocks"]]), 3) if sector["blocks"] else 0
        sector["risk_flags"] = sorted(set(sector["risk_flags"]))
    return [sectors[key] for key in sorted(sectors)]


def build_visual_report(dump_id: int) -> dict:
    dump = get_card_dump(dump_id)
    if not dump:
        return {}
    report = get_latest_report(dump_id)
    blocks = [_block_visual_object(row) for row in list_card_blocks(dump_id, 5000)]
    return {
        "dump": {
            "id": dump[0], "dump_name": dump[1], "file_name": dump[2], "file_type": dump[3],
            "file_path": dump[4], "sha256": dump[5], "size_bytes": dump[6], "card_type": dump[7],
            "uid": dump[8], "sak": dump[9], "atqa": dump[10], "block_count": dump[11],
            "sector_count": dump[12], "risk_level": dump[13], "summary": dump[14],
            "metadata": load_json(dump[15], {}), "duplicate_of": dump[16], "created_at": dump[17],
        },
        "report": report,
        "summary": report.get("summary", {}),
        "statistics": report.get("statistics", {}),
        "recommendations": report.get("recommendations", []),
        "risk_reasons": report.get("risk_reasons", []),
        "magic_findings": report.get("magic_findings", []),
        "mad_aid": report.get("mad_aid", []),
        "ndef": report.get("ndef", {"found": False, "tlvs": [], "records": []}),
        "blocks": blocks,
        "sectors": _group_blocks_by_sector(blocks),
    }
