from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from app.database.db import get_setting, set_setting
from app.hardware.com_port_scanner import scan_com_ports
from app.rf.card_dump_analyzer import (
    analyze_text_payload,
    build_visual_report,
    compare_dumps,
    ingest_card_dump,
    list_card_dumps,
    list_comparisons,
    list_pm3_events,
    parse_pm3_output,
)
from app.rf.protocol_catalog import (
    classify_command,
    get_protocol,
    list_protocols,
    protocol_summary,
    suggest_protocol_from_text,
)
from app.rf.smart_workflow import (
    create_smart_scan,
    get_smart_scan,
    launch_smart_scan,
    list_smart_scans,
    request_cancel,
    smart_scan_public_payload,
)
from app.rf_engine.proxmark3 import LAB_COMMANDS, current_mode, executar_comando_sync
from app.services.event_service import (
    add_proxmark_log,
    get_dashboard_summary,
    get_mifare_sector_map,
    get_mifare_summary,
    get_proxmark_logs,
    get_rfid_events,
)

api_bp = Blueprint("api_bp", __name__, url_prefix="/api")


def rows_to_dicts(rows, columns):
    return [dict(row) if hasattr(row, "keys") else {columns[i]: row[i] for i in range(min(len(columns), len(row)))} for row in rows]


def _payload():
    return request.get_json(silent=True) or request.form.to_dict()


def _configured_pm3():
    return get_setting("proxmark_client_path", ""), get_setting("proxmark_port", "COM5")


def _explicit_confirmation(value) -> bool:
    if value is True or value == 1:
        return True
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _bounded_int(value, default: int, minimum: int, maximum: int) -> int:
    if value in (None, ""):
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("O limite deve ser um numero inteiro.") from exc
    if not minimum <= parsed <= maximum:
        raise ValueError(f"O limite deve estar entre {minimum} e {maximum}.")
    return parsed


def _log_pm3_result(result):
    for log in result.get("logs", []):
        add_proxmark_log({
            "port": log.get("port"), "command": log.get("command"), "status": log.get("status"),
            "output": log.get("output"), "timestamp": log.get("timestamp"),
        })


def _run_pm3(command, timeout, confirm_sensitive=False):
    client_path, port = _configured_pm3()
    result = executar_comando_sync(client_path, command, port, timeout=timeout, confirm_sensitive=confirm_sensitive)
    _log_pm3_result(result)
    parsed = parse_pm3_output(result.get("output") or "") if result.get("output") else None
    return result, parsed


@api_bp.route("/status")
def status():
    return jsonify({"status": "ok", "app": "Utamo RFID / Proxmark3 Lab", "pm3_mode": current_mode(), "summary": get_dashboard_summary()})


@api_bp.route("/com-ports")
def com_ports():
    return jsonify({"ports": scan_com_ports()})


@api_bp.route("/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        data = _payload()
        if "proxmark_client_path" in data:
            value = str(data.get("proxmark_client_path") or "").strip().strip('"')
            if len(value) > 1024:
                return jsonify({"status": "error", "message": "Caminho muito longo."}), 400
            # This endpoint stores the administrator's explicit configuration. Run endpoints never accept a path.
            set_setting("proxmark_client_path", value)
        if "proxmark_port" in data:
            value = str(data.get("proxmark_port") or "").strip()
            if len(value) > 128:
                return jsonify({"status": "error", "message": "Porta inválida."}), 400
            set_setting("proxmark_port", value)
        if "mfc_key_file" in data:
            value = str(data.get("mfc_key_file") or "").strip().strip('"')
            if len(value) > 1024:
                return jsonify({"status": "error", "message": "Caminho do arquivo de chaves muito longo."}), 400
            set_setting("mfc_key_file", value)
    client_path, port = _configured_pm3()
    return jsonify({
        "status": "ok", "proxmark_client_path": client_path, "proxmark_port": port,
        "mfc_key_file": get_setting("mfc_key_file", ""),
        "pm3_mode": current_mode(), "max_timeout": current_app.config["PM3_MAX_TIMEOUT"],
    })


@api_bp.route("/proxmark/commands")
def pm3_commands():
    return jsonify({"commands": LAB_COMMANDS, "guard_mode": current_mode()})


@api_bp.route("/protocols")
def api_protocols():
    return jsonify({"status": "ok", "summary": protocol_summary(), "protocols": list_protocols(family=request.args.get("family"), query=request.args.get("q"))})


@api_bp.route("/protocols/<protocol_id>")
def api_protocol_detail(protocol_id):
    protocol = get_protocol(protocol_id)
    return jsonify({"status": "ok", "protocol": protocol}) if protocol else (jsonify({"status": "error", "message": "protocol not found"}), 404)


@api_bp.route("/protocols/classify-command", methods=["POST"])
def api_classify_command():
    return jsonify({"status": "ok", "classification": classify_command(_payload().get("command"), current_mode())})


@api_bp.route("/protocols/suggest", methods=["POST"])
def api_protocol_suggest():
    data = _payload()
    return jsonify({"status": "ok", "matches": suggest_protocol_from_text(data.get("text") or data.get("output") or "")})


@api_bp.route("/proxmark/run-profile", methods=["POST"])
def api_run_profile():
    data = _payload()
    protocol = get_protocol(data.get("protocol_id") or "")
    if not protocol:
        return jsonify({"status": "error", "message": "protocol not found"}), 404
    defaults = protocol.get("safe_commands") or []
    command = str(data.get("command") or (defaults[0] if defaults else "")).strip()
    result, parsed = _run_pm3(command, data.get("timeout", current_app.config["PM3_MAX_TIMEOUT"]), _explicit_confirmation(data.get("confirm_sensitive")))
    http_status = 403 if result.get("status") in {"blocked", "confirmation_required"} else (400 if result.get("status") == "error" else 200)
    return jsonify({"status": result.get("status"), "protocol": protocol, "command": command, "result": result, "parsed": parsed}), http_status


@api_bp.route("/proxmark/run", methods=["POST"])
def pm3_run():
    data = _payload()
    command = str(data.get("command") or "hf search").strip()
    result, parsed = _run_pm3(command, data.get("timeout", current_app.config["PM3_MAX_TIMEOUT"]), _explicit_confirmation(data.get("confirm_sensitive")))
    http_status = 403 if result.get("status") in {"blocked", "confirmation_required"} else (400 if result.get("status") == "error" else 200)
    return jsonify({"status": result.get("status"), "result": result, "parsed": parsed}), http_status


@api_bp.route("/smart-scan/start", methods=["POST"])
def smart_scan_start():
    data = _payload()
    client_path, port = _configured_pm3()
    if not client_path:
        return jsonify({"status": "error", "message": "Configure o caminho do cliente Proxmark3 antes da leitura inteligente."}), 400
    options = {
        "auto_dump": _explicit_confirmation(data.get("auto_dump", current_app.config.get("SMART_AUTO_DUMP", True))),
        "read_ndef": _explicit_confirmation(data.get("read_ndef", current_app.config.get("SMART_READ_NDEF", True))),
        "enforce_uid": _explicit_confirmation(data.get("enforce_uid", True)),
        "session_id": data.get("session_id") or None,
        "port": port,
    }
    job_id = create_smart_scan(options)
    launch_smart_scan(current_app._get_current_object(), job_id)
    job = smart_scan_public_payload(get_smart_scan(job_id))
    return jsonify({"status": "queued", "job": job}), 202


@api_bp.route("/smart-scan/<int:job_id>")
def smart_scan_status(job_id):
    job = smart_scan_public_payload(get_smart_scan(job_id))
    if not job:
        return jsonify({"status": "error", "message": "Leitura inteligente não encontrada."}), 404
    return jsonify({"status": "ok", "job": job})


@api_bp.route("/smart-scan/<int:job_id>/cancel", methods=["POST"])
def smart_scan_cancel(job_id):
    job = get_smart_scan(job_id)
    if not job:
        return jsonify({"status": "error", "message": "Leitura inteligente não encontrada."}), 404
    if job.get("terminal"):
        return jsonify({"status": "error", "message": "A leitura já foi finalizada."}), 409
    if not request_cancel(job_id):
        return jsonify({"status": "error", "message": "Não foi possível solicitar o cancelamento."}), 409
    return jsonify({"status": "ok", "message": "Cancelamento solicitado."})


@api_bp.route("/smart-scans")
def smart_scan_list():
    try:
        limit = _bounded_int(request.args.get("limit"), 50, 1, 500)
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    return jsonify({"status": "ok", "jobs": list_smart_scans(limit)})


@api_bp.route("/proxmark/parse-output", methods=["POST"])
def pm3_parse():
    data = _payload()
    return jsonify({"status": "ok", "parsed": parse_pm3_output(data.get("output") or data.get("line") or "", source="operator_paste")})


@api_bp.route("/proxmark/events")
def pm3_events():
    return jsonify({"events": rows_to_dicts(list_pm3_events(100), ["id", "source", "event_type", "uid", "protocol", "severity", "summary", "created_at"])})


@api_bp.route("/proxmark/logs")
def logs():
    return jsonify({"logs": get_proxmark_logs(200)})


@api_bp.route("/rfid/events")
def events():
    return jsonify({"events": get_rfid_events(200)})


@api_bp.route("/card-dump/analyze", methods=["POST"])
def card_dump_analyze():
    if request.files.get("dump_file"):
        uploaded = request.files["dump_file"]
        content = uploaded.read()
        if not content:
            return jsonify({"status": "error", "message": "Arquivo vazio."}), 400
        try:
            result = ingest_card_dump(uploaded.filename or "upload.dump", content, request.form.get("dump_name") or uploaded.filename)
        except (TypeError, ValueError) as exc:
            return jsonify({"status": "error", "message": str(exc)}), 400
        return jsonify({"status": "ok", **result})
    data = _payload()
    if "content" in data:
        content = str(data.get("content") or "")
        if not content.strip():
            return jsonify({"status": "error", "message": "Conteúdo vazio."}), 400
        try:
            result = analyze_text_payload(data.get("name") or "api_payload.eml", content)
        except (TypeError, ValueError) as exc:
            return jsonify({"status": "error", "message": str(exc)}), 400
        return jsonify({"status": "ok", **result})
    return jsonify({"status": "error", "message": "Envie multipart dump_file ou JSON com content."}), 400


@api_bp.route("/card-dump/list")
def card_dump_list():
    return jsonify({"dumps": rows_to_dicts(list_card_dumps(100), ["id", "dump_name", "file_name", "file_type", "card_type", "uid", "block_count", "sector_count", "risk_level", "summary", "created_at"])})


@api_bp.route("/card-dump/<int:dump_id>")
def card_dump_detail(dump_id):
    data = build_visual_report(dump_id)
    return jsonify({"status": "ok", **data}) if data else (jsonify({"status": "error", "message": "dump not found"}), 404)


@api_bp.route("/card-dump/compare", methods=["POST"])
def card_dump_compare():
    data = _payload()
    try:
        dump_a, dump_b = int(data.get("dump_a")), int(data.get("dump_b"))
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "dump_a e dump_b devem ser IDs inteiros."}), 400
    if dump_a == dump_b:
        return jsonify({"status": "error", "message": "Selecione dumps diferentes."}), 400
    try:
        comparison = compare_dumps(dump_a, dump_b)
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 404
    return jsonify({"status": "ok", "comparison": comparison})


@api_bp.route("/card-dump/comparisons")
def card_dump_comparisons():
    return jsonify({"comparisons": rows_to_dicts(list_comparisons(100), ["id", "dump_a", "dump_b", "similarity", "changed_blocks", "static_similarity_score", "comparison_status", "created_at"])})


@api_bp.route("/mifare/import", methods=["POST"])
def api_mifare_import():
    data = _payload()
    uid = str(data.get("card_uid") or "api-card").strip()[:64]
    dump_text = str(data.get("dump_text") or "")
    if not dump_text.strip():
        return jsonify({"status": "error", "message": "dump_text vazio."}), 400
    try:
        result = analyze_text_payload(f"{uid}.eml", dump_text)
    except (TypeError, ValueError) as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    return jsonify({"status": "ok", "analysis": result})


@api_bp.route("/mifare/<card_uid>")
def api_mifare_detail(card_uid):
    return jsonify({"summary": get_mifare_summary(card_uid), "sectors": get_mifare_sector_map(card_uid)})
