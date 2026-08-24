from __future__ import annotations

import json

from flask import Blueprint, abort, current_app, jsonify, redirect, render_template, request, send_file

from app.database.db import get_setting, set_setting
from app.rf.card_dump_analyzer import (
    analyze_text_payload,
    build_visual_report,
    compare_dumps,
    ingest_card_dump,
    list_card_dumps,
    parse_pm3_output,
)
from app.rf.report_exporter import export_report_csv, export_report_html, export_report_json, export_report_pdf
from app.rf.session_manager import (
    add_favorite,
    add_history,
    add_session_command,
    add_session_dump,
    create_session,
    get_favorites,
    get_history,
    get_session,
    list_sessions,
)
from app.rf.smart_workflow import get_smart_scan, list_smart_scans
from app.rf_engine.proxmark3 import LAB_COMMANDS, current_mode, executar_comando_sync
from app.services.event_service import (
    add_proxmark_log,
    clear_mifare_blocks,
    clear_proxmark_logs,
    clear_rfid_events,
    get_mifare_sector_map,
    get_mifare_summary,
)

rfid_bp = Blueprint("rfid_bp", __name__)


def rows_to_dicts(rows, columns):
    return [dict(row) if hasattr(row, "keys") else {columns[i]: row[i] for i in range(min(len(columns), len(row)))} for row in rows]


def _configured_pm3():
    return get_setting("proxmark_client_path", ""), get_setting("proxmark_port", "COM5")


@rfid_bp.route("/settings/proxmark", methods=["POST"])
def proxmark_settings():
    client_path = str(request.form.get("proxmark_client_path") or "").strip().strip('"')
    port = str(request.form.get("proxmark_port") or "").strip()
    if len(client_path) > 1024 or len(port) > 128:
        return render_template("dump_error.html", title="Configuração inválida", error="Caminho ou porta acima do limite."), 400
    key_file = str(request.form.get("mfc_key_file") or "").strip().strip('"')
    if len(key_file) > 1024:
        return render_template("dump_error.html", title="Configuração inválida", error="Caminho do arquivo de chaves acima do limite."), 400
    set_setting("proxmark_client_path", client_path)
    set_setting("proxmark_port", port or "COM5")
    set_setting("mfc_key_file", key_file)
    return redirect("/lab#configuration")


@rfid_bp.route("/proxmark/run", methods=["POST"])
def proxmark_run():
    client_path, port = _configured_pm3()
    command = str(request.form.get("command") or "hf search").strip()
    session_id = request.form.get("session_id") or ""
    result = executar_comando_sync(
        client_path,
        command,
        port,
        timeout=request.form.get("timeout") or current_app.config["PM3_MAX_TIMEOUT"],
        confirm_sensitive=request.form.get("confirm_sensitive") == "1",
    )
    for log in result.get("logs", []):
        add_proxmark_log({"port": log.get("port") or port, "command": log.get("command") or command, "status": log.get("status"), "output": log.get("output"), "timestamp": log.get("timestamp")})
    parsed = None
    if result.get("output"):
        try:
            parsed = parse_pm3_output(result["output"])
        except Exception as exc:
            add_proxmark_log({"port": port, "command": command, "status": "PARSE_ERROR", "output": str(exc)})
    add_history(port, command, result.get("status"))
    if session_id:
        try:
            add_session_command(int(session_id), port, command, result.get("status"), result.get("output") or "", parsed)
        except (TypeError, ValueError):
            pass
    return redirect("/lab#proxmark")


@rfid_bp.route("/proxmark/parse", methods=["POST"])
def proxmark_parse():
    parsed = parse_pm3_output(request.form.get("output", ""), source="operator_paste")
    add_proxmark_log({"port": "manual", "command": "parse-output", "status": "PARSED", "output": json.dumps(parsed, ensure_ascii=False)})
    return redirect("/lab#events")


@rfid_bp.route("/card-dump/upload", methods=["POST"])
def card_dump_upload():
    uploaded = request.files.get("dump_file")
    if not uploaded:
        return redirect("/dumps#import")
    try:
        content = uploaded.read()
        if not content:
            raise ValueError("Arquivo vazio.")
        result = ingest_card_dump(uploaded.filename or "upload.dump", content, request.form.get("dump_name") or uploaded.filename)
    except Exception as exc:
        return render_template("dump_error.html", title="Erro ao importar dump", error=str(exc)), 400
    session_id = request.form.get("session_id")
    if session_id:
        try:
            add_session_dump(int(session_id), int(result.get("dump_id")))
        except (TypeError, ValueError):
            pass
    suffix = f"?duplicate_of={result.get('duplicate_of')}" if result.get("duplicate_of") else ""
    return redirect(f"/card-dump/{result.get('dump_id')}{suffix}")


@rfid_bp.route("/card-dump/text", methods=["POST"])
def card_dump_text():
    name, content = request.form.get("name") or "manual_dump.eml", request.form.get("content") or ""
    try:
        if not content.strip():
            raise ValueError("Conteúdo vazio.")
        result = analyze_text_payload(name, content)
    except Exception as exc:
        return render_template("dump_error.html", title="Erro ao analisar texto", error=str(exc)), 400
    return redirect(f"/card-dump/{result.get('dump_id')}")


@rfid_bp.route("/mifare/import", methods=["POST"])
def mifare_import():
    uid, dump_text = request.form.get("card_uid") or "manual-card", request.form.get("dump_text") or ""
    try:
        if not dump_text.strip():
            raise ValueError("Conteúdo vazio.")
        result = analyze_text_payload(f"{uid}.eml", dump_text)
        return redirect(f"/card-dump/{result.get('dump_id')}")
    except Exception as exc:
        return render_template("dump_error.html", title="Erro ao analisar MIFARE", error=str(exc)), 400


@rfid_bp.route("/mifare/<card_uid>")
def mifare_detail(card_uid):
    return render_template("mifare_detail.html", card_uid=card_uid, summary=get_mifare_summary(card_uid), sectors=get_mifare_sector_map(card_uid))


@rfid_bp.route("/card-dump/<int:dump_id>")
def card_dump_detail(dump_id):
    data = build_visual_report(dump_id)
    if not data:
        abort(404)
    return render_template("dump_detail.html", data=data)


@rfid_bp.route("/compare", methods=["GET", "POST"])
def compare_ui():
    dumps = rows_to_dicts(list_card_dumps(500), ["id", "dump_name", "file_name", "file_type", "card_type", "uid", "block_count", "sector_count", "risk_level", "summary", "created_at"])
    comparison = None
    error = None
    if request.method == "POST":
        try:
            dump_a, dump_b = int(request.form.get("dump_a")), int(request.form.get("dump_b"))
            if dump_a == dump_b:
                raise ValueError("Selecione dois dumps diferentes.")
            comparison = compare_dumps(dump_a, dump_b)
        except (TypeError, ValueError) as exc:
            error = str(exc)
    return render_template("compare.html", title="Comparação estática de dumps", dumps=dumps, comparison=comparison, error=error)


@rfid_bp.route("/maintenance/clear-logs", methods=["POST"])
def clear_logs():
    clear_proxmark_logs()
    return redirect("/lab#logs")


@rfid_bp.route("/maintenance/clear-events", methods=["POST"])
def clear_events():
    clear_rfid_events()
    return redirect("/lab#events")


@rfid_bp.route("/maintenance/clear-mifare", methods=["POST"])
def clear_mifare():
    clear_mifare_blocks()
    return redirect("/dumps#mifare-cards")


@rfid_bp.route("/commands")
def command_list():
    return jsonify({"commands": LAB_COMMANDS, "guard_mode": current_mode()})


@rfid_bp.route("/smart-scans")
def smart_scans_page():
    return render_template("smart_scans.html", title="Leituras inteligentes", jobs=list_smart_scans(200))


@rfid_bp.route("/smart-scan/<int:job_id>")
def smart_scan_detail(job_id):
    data = get_smart_scan(job_id, include_outputs=True)
    if not data:
        abort(404)
    return render_template("smart_scan_detail.html", title=f"Leitura inteligente #{job_id}", data=data)


@rfid_bp.route("/sessions", methods=["GET", "POST"])
def sessions_page():
    if request.method == "POST":
        sid = create_session(request.form.get("name"), request.form.get("description"))
        return redirect(f"/sessions/{sid}")
    return render_template("sessions.html", title="Sessões de laboratório", sessions=list_sessions(200))


@rfid_bp.route("/sessions/<int:session_id>")
def session_detail(session_id):
    data = get_session(session_id)
    if not data:
        abort(404)
    return render_template("session_detail.html", title="Sessão de laboratório", data=data, favorites=get_favorites(), history=get_history(30))


@rfid_bp.route("/commands/favorite", methods=["POST"])
def command_favorite():
    command = str(request.form.get("command") or "").strip()
    if command:
        add_favorite(request.form.get("name"), command, request.form.get("protocol") or "Custom")
    return redirect(request.referrer or "/lab")


@rfid_bp.route("/card-dump/<int:dump_id>/export/<fmt>")
def export_dump_report(dump_id, fmt):
    exporters = {"json": export_report_json, "html": export_report_html, "csv": export_report_csv, "pdf": export_report_pdf}
    exporter = exporters.get(str(fmt or "").lower())
    if not exporter:
        abort(404)
    try:
        path = exporter(dump_id)
    except ValueError:
        # Unknown dump/report must be a client error, not an HTTP 500.
        abort(404)
    return send_file(path, as_attachment=True)


@rfid_bp.route("/rf/intelligence")
@rfid_bp.route("/rf/advanced")
@rfid_bp.route("/rf/hardware")
@rfid_bp.route("/rf/ops")
def removed_rf_modules():
    return redirect("/")
