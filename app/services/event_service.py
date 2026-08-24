from __future__ import annotations

from datetime import datetime

from app.database.db import get_connection, init_db, transaction
from app.rf.card_dump_analyzer import DEFAULT_KEYS, clean_hex
from app.rfid.mifare_parser import analyze_mifare_classic_dump

init_db()


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def add_rfid_event(event):
    with transaction() as conn:
        conn.execute(
            """INSERT INTO rfid_events(source,reader,card_type,uid,sak,atqa,event_type,description,timestamp)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (event.get("source"), event.get("reader"), event.get("card_type"), event.get("uid"), event.get("sak"),
             event.get("atqa"), event.get("event_type"), event.get("description"), event.get("timestamp", now_str())),
        )


def get_rfid_events(limit=100):
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT id,source,reader,card_type,uid,sak,atqa,event_type,description,timestamp FROM rfid_events ORDER BY id DESC LIMIT ?",
            (max(1, min(1000, int(limit or 100))),),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def clear_rfid_events():
    with transaction() as conn:
        conn.execute("DELETE FROM rfid_events")


def save_mifare_blocks(blocks, replace_uid=None):
    with transaction() as conn:
        if replace_uid:
            conn.execute("DELETE FROM mifare_blocks WHERE card_uid=?", (replace_uid,))
        conn.executemany(
            """INSERT INTO mifare_blocks(card_uid,sector,block,block_type,data_hex,ascii_preview,key_a,access_bits,key_b,timestamp)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            [(
                block.get("card_uid"), block.get("sector"), block.get("block"), block.get("block_type"),
                block.get("data_hex"), block.get("ascii_preview"), block.get("key_a"), block.get("access_bits"),
                block.get("key_b"), block.get("timestamp", now_str()),
            ) for block in blocks],
        )


def import_mifare_dump(card_uid, dump_text):
    analysis = analyze_mifare_classic_dump(card_uid, dump_text)
    save_mifare_blocks(analysis.get("blocks", []), replace_uid=card_uid)
    add_rfid_event({
        "source": "mifare_import",
        "reader": "static_dump",
        "card_type": analysis.get("summary", {}).get("card_type", "MIFARE Classic"),
        "uid": card_uid,
        "event_type": "MIFARE_DUMP_IMPORTED",
        "description": f"Importados {len(analysis.get('blocks', []))} blocos pelo motor normalizado.",
    })
    return analysis


def get_mifare_blocks(card_uid=None, limit=300):
    conn = get_connection()
    try:
        if card_uid:
            rows = conn.execute("SELECT * FROM mifare_blocks WHERE card_uid=? ORDER BY sector,block", (card_uid,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM mifare_blocks ORDER BY id DESC LIMIT ?", (max(1, min(5000, int(limit or 300))),)).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_mifare_cards():
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT card_uid,COUNT(*) AS total_blocks,MAX(timestamp) AS last_seen FROM mifare_blocks GROUP BY card_uid ORDER BY last_seen DESC"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_mifare_summary(card_uid):
    blocks = get_mifare_blocks(card_uid)
    sectors = {block["sector"] for block in blocks}
    trailers = [block for block in blocks if block.get("block_type") == "trailer"]
    default_sectors = {
        block.get("sector") for block in trailers
        if clean_default_key(block.get("key_a")) or clean_default_key(block.get("key_b"))
    }
    readable = sum(sum(ch != "." for ch in str(block.get("ascii_preview", ""))) >= 4 for block in blocks)
    return {
        "card_uid": card_uid,
        "total_blocks": len(blocks),
        "total_sectors": len(sectors),
        "trailer_blocks": len(trailers),
        "default_key_sectors": len(default_sectors),
        "readable_blocks": readable,
    }


def clean_default_key(value) -> bool:
    return clean_hex(value) in DEFAULT_KEYS


def get_mifare_sector_map(card_uid):
    sectors = {}
    for block in get_mifare_blocks(card_uid):
        sid = str(block["sector"])
        sector = sectors.setdefault(sid, {"sector": block["sector"], "blocks": [], "has_trailer": False, "contains_default_keys": False, "contains_ascii": False})
        sector["blocks"].append(block)
        if block.get("block_type") == "trailer":
            sector["has_trailer"] = True
            sector["contains_default_keys"] = clean_default_key(block.get("key_a")) or clean_default_key(block.get("key_b"))
        if sum(ch != "." for ch in str(block.get("ascii_preview", ""))) >= 4:
            sector["contains_ascii"] = True
    return [sectors[key] for key in sorted(sectors, key=int)]


def clear_mifare_blocks():
    with transaction() as conn:
        conn.execute("DELETE FROM mifare_blocks")


def add_proxmark_log(log):
    with transaction() as conn:
        conn.execute(
            "INSERT INTO proxmark_logs(port,command,status,output,timestamp) VALUES (?,?,?,?,?)",
            (log.get("port"), log.get("command"), log.get("status"), log.get("output"), log.get("timestamp", now_str())),
        )


def get_proxmark_logs(limit=80, output_limit: int | None = None):
    row_limit = max(1, min(1000, int(limit or 80)))
    conn = get_connection()
    try:
        if output_limit is None:
            rows = conn.execute(
                "SELECT id,port,command,status,output,timestamp FROM proxmark_logs ORDER BY id DESC LIMIT ?",
                (row_limit,),
            ).fetchall()
        else:
            preview_limit = max(128, min(20_000, int(output_limit)))
            rows = conn.execute(
                """
                SELECT id,port,command,status,
                       CASE
                         WHEN length(COALESCE(output, '')) > ?
                         THEN substr(output, 1, ?) || char(10) || '… [saída truncada na interface]'
                         ELSE output
                       END AS output,
                       timestamp
                FROM proxmark_logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (preview_limit, preview_limit, row_limit),
            ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def clear_proxmark_logs():
    with transaction() as conn:
        conn.execute("DELETE FROM proxmark_logs")


def get_dashboard_summary():
    conn = get_connection()
    try:
        def one(sql):
            return conn.execute(sql).fetchone()[0]

        return {
            "rfid_events": one("SELECT COUNT(*) FROM rfid_events"),
            "proxmark_logs": one("SELECT COUNT(*) FROM proxmark_logs"),
            "mifare_cards": one("SELECT COUNT(DISTINCT card_uid) FROM mifare_blocks"),
            "card_dumps": one("SELECT COUNT(*) FROM rfid_card_dumps"),
            "pm3_events": one("SELECT COUNT(*) FROM rfid_pm3_events"),
        }
    finally:
        conn.close()
