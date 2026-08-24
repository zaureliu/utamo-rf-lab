from flask import Blueprint, render_template

from app.database.db import get_setting
from app.hardware.com_port_scanner import scan_com_ports
from app.rf.card_dump_analyzer import init_card_dump_tables, list_card_dumps, list_pm3_events
from app.rf.protocol_catalog import list_protocols, protocol_summary
from app.rf.session_manager import get_favorites, get_history, list_sessions
from app.rf.smart_workflow import list_smart_scans
from app.services.event_service import get_dashboard_summary, get_mifare_cards, get_proxmark_logs

dashboard_bp = Blueprint("dashboard_bp", __name__)


def rows_to_dicts(rows, columns):
    out = []
    for r in rows:
        if hasattr(r, "keys"):
            out.append(dict(r))
        else:
            out.append({columns[i]: r[i] for i in range(min(len(columns), len(r)))})
    return out


def _dumps(limit=100):
    return rows_to_dicts(
        list_card_dumps(limit),
        ["id","dump_name","file_name","file_type","card_type","uid","block_count","sector_count","risk_level","summary","created_at"]
    )


def _pm3_events(limit=50):
    return rows_to_dicts(
        list_pm3_events(limit),
        ["id","source","event_type","uid","protocol","severity","summary","created_at"]
    )


@dashboard_bp.route("/")
def index():
    init_card_dump_tables()
    return render_template(
        "index.html",
        title="Utamo RF Lab - Início",
        summary=get_dashboard_summary(),
        dumps=_dumps(8),
        pm3_events=_pm3_events(8),
    )


@dashboard_bp.route("/lab")
def lab():
    init_card_dump_tables()
    return render_template(
        "lab.html",
        title="Utamo RF Lab - Proxmark3",
        ports=scan_com_ports(),
        logs=get_proxmark_logs(50, output_limit=2000),
        pm3_events=_pm3_events(40),
        client_path=get_setting("proxmark_client_path", ""),
        default_port=get_setting("proxmark_port", "COM5"),
        mfc_key_file=get_setting("mfc_key_file", ""),
        smart_scans=list_smart_scans(12),
        protocols=list_protocols(),
        sessions=list_sessions(50),
        favorites=get_favorites(),
        history=get_history(50),
    )


@dashboard_bp.route("/dumps")
def dumps_page():
    init_card_dump_tables()
    return render_template(
        "dumps.html",
        title="Utamo RF Lab - Dumps",
        dumps=_dumps(200),
        mifare_cards=get_mifare_cards(),
        sessions=list_sessions(50),
    )


@dashboard_bp.route("/protocols")
def protocols_page():
    return render_template(
        "protocols.html",
        title="Utamo RF Lab - Protocolos",
        protocols=list_protocols(),
        protocol_summary=protocol_summary(),
    )
