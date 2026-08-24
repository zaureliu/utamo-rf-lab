from __future__ import annotations

import csv
import html
import json
import os
from datetime import datetime

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False

from app.rf.card_dump_analyzer import REPORT_DIR, get_card_dump, get_latest_report, sanitize_report_keys


def _ts():
    return datetime.now().strftime("%Y%m%d_%H%M%S_%f")


def _data(dump_id: int) -> dict:
    dump = get_card_dump(dump_id)
    report = get_latest_report(dump_id)
    if not dump or not report:
        raise ValueError("Dump ou relatório não encontrado.")
    full_keys = os.environ.get("UTAMO_EXPORT_FULL_KEYS", "").strip().lower() in {"1", "true", "yes", "on"}
    result = sanitize_report_keys(report, full_keys=full_keys)
    result["export_policy"] = {"keys_masked": not full_keys, "full_key_export_requires": "UTAMO_EXPORT_FULL_KEYS=1"}
    result["dump_record"] = {
        "id": dump[0], "dump_name": dump[1], "file_name": dump[2], "file_type": dump[3], "sha256": dump[5],
        "size_bytes": dump[6], "card_type": dump[7], "uid": dump[8], "sak": dump[9], "atqa": dump[10],
        "block_count": dump[11], "sector_count": dump[12], "risk_level": dump[13], "created_at": dump[17],
    }
    return result


def export_report_json(dump_id):
    data = _data(dump_id)
    path = REPORT_DIR / f"dump_{dump_id}_export_{_ts()}.json"
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def export_report_html(dump_id):
    data = _data(dump_id)
    d = data.get("dump_record", {})
    rows = []
    for block in data.get("blocks", []):
        rows.append(
            "<tr>" + "".join([
                f"<td>{html.escape(str(block.get('sector', '')))}</td>",
                f"<td>{html.escape(str(block.get('block_index', '')))}</td>",
                f"<td>{html.escape(str(block.get('absolute_block', '')))}</td>",
                f"<td><code>{html.escape(str(block.get('block_hex', '')))}</code></td>",
                f"<td><code>{html.escape(str(block.get('ascii', '')))}</code></td>",
                f"<td><code>{html.escape(str(block.get('key_a', '')))}</code></td>",
                f"<td><code>{html.escape(str(block.get('key_b', '')))}</code></td>",
            ]) + "</tr>"
        )
    document = f"""<!doctype html><html lang='pt-br'><head><meta charset='utf-8'><title>Utamo RFID Dump #{dump_id}</title>
<style>body{{font-family:Arial,sans-serif;padding:24px}}table{{width:100%;border-collapse:collapse}}td,th{{border:1px solid #999;padding:6px;text-align:left}}code{{word-break:break-all}}</style></head><body>
<h1>Utamo RFID / Proxmark3 Lab — Dump #{dump_id}</h1>
<p><b>Nome:</b> {html.escape(str(d.get('dump_name','')))}<br><b>Tipo:</b> {html.escape(str(d.get('card_type','')))}<br><b>UID:</b> {html.escape(str(d.get('uid') or '--'))}<br><b>Risco:</b> {html.escape(str(d.get('risk_level','')))}<br><b>SHA-256:</b> <code>{html.escape(str(d.get('sha256','')))}</code></p>
<p><b>Política de exportação:</b> chaves {'mascaradas' if data.get('export_policy',{}).get('keys_masked') else 'integrais por configuração explícita'}.</p>
<h2>Recomendações</h2><ul>{''.join('<li>'+html.escape(str(item))+'</li>' for item in data.get('recommendations', []))}</ul>
<h2>Blocos/Páginas</h2><table><tr><th>Setor</th><th>Índice</th><th>Absoluto</th><th>Hex</th><th>ASCII</th><th>Key A</th><th>Key B</th></tr>{''.join(rows)}</table>
</body></html>"""
    path = REPORT_DIR / f"dump_{dump_id}_report_{_ts()}.html"
    path.write_text(document, encoding="utf-8")
    return path


def _csv_safe(value):
    """Neutralize spreadsheet formula injection (=, +, -, @, tab, CR prefixes)."""
    text = str(value if value is not None else "")
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text


def export_report_csv(dump_id):
    data = _data(dump_id)
    path = REPORT_DIR / f"dump_{dump_id}_blocks_{_ts()}.csv"
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["sector", "block_index", "absolute_block", "type", "hex", "ascii", "key_a", "access_bits", "key_b", "annotations"])
        for block in data.get("blocks", []):
            writer.writerow([
                _csv_safe(block.get("sector")), _csv_safe(block.get("block_index")), _csv_safe(block.get("absolute_block")),
                "trailer" if block.get("is_trailer") else "data", _csv_safe(block.get("block_hex")), _csv_safe(block.get("ascii")),
                _csv_safe(block.get("key_a")), _csv_safe(block.get("access_bits")), _csv_safe(block.get("key_b")),
                _csv_safe(";".join(map(str, block.get("annotations", [])))),
            ])
    return path


def export_report_pdf(dump_id):
    if not REPORTLAB_AVAILABLE:
        return export_report_html(dump_id)
    data = _data(dump_id)
    d = data.get("dump_record", {})
    path = REPORT_DIR / f"dump_{dump_id}_report_{_ts()}.pdf"
    styles = getSampleStyleSheet()
    document = SimpleDocTemplate(str(path), pagesize=A4)
    story = [Paragraph(f"Utamo RFID / Proxmark3 Lab — Dump #{dump_id}", styles["Title"]), Spacer(1, 12)]
    for label, value in (("Nome", d.get("dump_name")), ("Tipo", d.get("card_type")), ("UID", d.get("uid") or "--"), ("Risco", d.get("risk_level")), ("SHA-256", d.get("sha256"))):
        story.append(Paragraph(f"<b>{html.escape(str(label))}:</b> {html.escape(str(value or ''))}", styles["Normal"]))
    story.append(Paragraph("Chaves são mascaradas por padrão nas exportações.", styles["Normal"]))
    story.append(Spacer(1, 12))
    table_data = [["Setor", "Índice", "Abs", "Tipo", "Hex"]]
    for block in data.get("blocks", [])[:120]:
        table_data.append([block.get("sector"), block.get("block_index"), block.get("absolute_block"), "T" if block.get("is_trailer") else "D", str(block.get("block_hex", ""))[:32]])
    table = Table(table_data, repeatRows=1)
    table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey), ("FONTSIZE", (0, 0), (-1, -1), 7)]))
    story.append(table)
    document.build(story)
    return path
