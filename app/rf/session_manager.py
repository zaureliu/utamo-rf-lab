from __future__ import annotations

import json
from datetime import datetime

from app.database.db import get_connection, init_db, transaction


def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _json(value) -> str:
    try:
        return json.dumps(value or {}, ensure_ascii=False)
    except (TypeError, ValueError):
        return "{}"


def init_session_tables() -> None:
    init_db()
    seed_favorites()


def seed_favorites() -> None:
    favorites = [
        ("Hardware version", "hw version", "Hardware"),
        ("Tune antenas", "hw tune", "Hardware"),
        ("Buscar HF", "hf search", "HF"),
        ("ISO14443-A info", "hf 14a info", "ISO14443-A"),
        ("MIFARE info", "hf mf info", "MIFARE Classic"),
        ("Buscar LF", "lf search", "LF"),
        ("EM410x reader", "lf em 410x reader", "EM410x"),
        ("HID reader", "lf hid reader", "HID Prox"),
    ]
    with transaction() as conn:
        conn.executemany(
            "INSERT OR IGNORE INTO command_favorites(name,command,protocol,created_at) VALUES(?,?,?,?)",
            [(name, command, protocol, now()) for name, command, protocol in favorites],
        )


def create_session(name, description=""):
    init_session_tables()
    with transaction() as conn:
        cursor = conn.execute(
            "INSERT INTO lab_sessions(name,description,status,created_at,updated_at) VALUES(?,?,?,?,?)",
            (name or f"Sessão {now()}", description or "", "OPEN", now(), now()),
        )
        return cursor.lastrowid


def list_sessions(limit=100):
    init_session_tables()
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM lab_sessions ORDER BY id DESC LIMIT ?",
            (max(1, min(1000, int(limit or 100))),),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_session(session_id):
    init_session_tables()
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM lab_sessions WHERE id=?", (session_id,)).fetchone()
        if not row:
            return None
        commands = conn.execute(
            "SELECT * FROM lab_session_commands WHERE session_id=? ORDER BY id DESC",
            (session_id,),
        ).fetchall()
        dumps = conn.execute(
            """SELECT lsd.id,lsd.dump_id,lsd.created_at,d.dump_name,d.card_type,d.uid,d.risk_level
               FROM lab_session_dumps lsd
               LEFT JOIN rfid_card_dumps d ON d.id=lsd.dump_id
               WHERE lsd.session_id=? ORDER BY lsd.id DESC""",
            (session_id,),
        ).fetchall()
        return {"session": dict(row), "commands": [dict(item) for item in commands], "dumps": [dict(item) for item in dumps]}
    finally:
        conn.close()


def add_session_command(session_id, port, command, status, output, parsed=None):
    if not session_id:
        return None
    init_session_tables()
    with transaction() as conn:
        cursor = conn.execute(
            "INSERT INTO lab_session_commands(session_id,port,command,status,output,parsed_json,created_at) VALUES(?,?,?,?,?,?,?)",
            (session_id, port, command, status, output, _json(parsed), now()),
        )
        conn.execute("UPDATE lab_sessions SET updated_at=? WHERE id=?", (now(), session_id))
        return cursor.lastrowid


def add_session_dump(session_id, dump_id):
    if not session_id or not dump_id:
        return None
    init_session_tables()
    with transaction() as conn:
        cursor = conn.execute(
            "INSERT OR IGNORE INTO lab_session_dumps(session_id,dump_id,created_at) VALUES(?,?,?)",
            (session_id, dump_id, now()),
        )
        conn.execute("UPDATE lab_sessions SET updated_at=? WHERE id=?", (now(), session_id))
        return cursor.lastrowid


def add_history(port, command, status):
    init_session_tables()
    with transaction() as conn:
        conn.execute(
            "INSERT INTO command_history(port,command,status,created_at) VALUES(?,?,?,?)",
            (port, command, status, now()),
        )


def get_history(limit=50):
    init_session_tables()
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM command_history ORDER BY id DESC LIMIT ?",
            (max(1, min(1000, int(limit or 50))),),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_favorites():
    init_session_tables()
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM command_favorites ORDER BY protocol,name").fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def add_favorite(name, command, protocol="Custom"):
    init_session_tables()
    with transaction() as conn:
        conn.execute(
            """INSERT INTO command_favorites(name,command,protocol,created_at) VALUES(?,?,?,?)
               ON CONFLICT(command) DO UPDATE SET name=excluded.name,protocol=excluded.protocol,created_at=excluded.created_at""",
            (name or command, command, protocol or "Custom", now()),
        )
