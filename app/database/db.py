from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RUNTIME_DIR = Path(os.environ.get("UTAMO_RUNTIME_DIR") or PROJECT_ROOT / "runtime").resolve()
RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.environ.get("UTAMO_RF_DB_PATH") or RUNTIME_DIR / "utamo_rfid_lab.db").resolve()
SCHEMA_VERSION = 6


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def get_conn() -> sqlite3.Connection:
    """Compatibility alias used by the analysis and session layers."""
    return get_connection()


@contextmanager
def transaction():
    conn = get_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT,
            action TEXT NOT NULL,
            target TEXT,
            outcome TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS rfid_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT,
            reader TEXT,
            card_type TEXT,
            uid TEXT,
            sak TEXT,
            atqa TEXT,
            event_type TEXT,
            description TEXT,
            timestamp TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS mifare_blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            card_uid TEXT NOT NULL,
            sector INTEGER NOT NULL,
            block INTEGER NOT NULL,
            block_type TEXT,
            data_hex TEXT NOT NULL,
            ascii_preview TEXT,
            key_a TEXT,
            access_bits TEXT,
            key_b TEXT,
            timestamp TEXT NOT NULL,
            UNIQUE(card_uid, block)
        );

        CREATE TABLE IF NOT EXISTS proxmark_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            port TEXT,
            command TEXT,
            status TEXT,
            output TEXT,
            timestamp TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS proxmark_runtime_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_version TEXT,
            firmware_version TEXT,
            bootrom_version TEXT,
            source_command TEXT,
            raw_excerpt TEXT,
            observed_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS rfid_card_dumps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dump_name TEXT NOT NULL,
            file_name TEXT NOT NULL,
            file_type TEXT NOT NULL,
            file_path TEXT,
            sha256 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            card_type TEXT NOT NULL,
            uid TEXT,
            sak TEXT,
            atqa TEXT,
            block_count INTEGER NOT NULL DEFAULT 0,
            sector_count INTEGER NOT NULL DEFAULT 0,
            risk_level TEXT NOT NULL,
            summary TEXT,
            metadata TEXT,
            duplicate_of INTEGER REFERENCES rfid_card_dumps(id) ON DELETE SET NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS rfid_card_blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dump_id INTEGER NOT NULL REFERENCES rfid_card_dumps(id) ON DELETE CASCADE,
            sector INTEGER NOT NULL,
            block_index INTEGER NOT NULL,
            absolute_block INTEGER NOT NULL,
            block_hex TEXT NOT NULL,
            is_trailer INTEGER NOT NULL DEFAULT 0,
            key_a TEXT,
            access_bits TEXT,
            key_b TEXT,
            is_empty INTEGER NOT NULL DEFAULT 0,
            has_default_key INTEGER NOT NULL DEFAULT 0,
            annotations TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(dump_id, absolute_block)
        );

        CREATE TABLE IF NOT EXISTS rfid_card_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dump_id INTEGER NOT NULL REFERENCES rfid_card_dumps(id) ON DELETE CASCADE,
            report_path TEXT,
            report_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS rfid_dump_comparisons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dump_a INTEGER NOT NULL REFERENCES rfid_card_dumps(id) ON DELETE CASCADE,
            dump_b INTEGER NOT NULL REFERENCES rfid_card_dumps(id) ON DELETE CASCADE,
            similarity REAL NOT NULL,
            changed_blocks INTEGER NOT NULL,
            static_similarity_score INTEGER NOT NULL,
            comparison_status TEXT NOT NULL,
            report_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS rfid_pm3_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT,
            event_type TEXT,
            uid TEXT,
            protocol TEXT,
            severity TEXT,
            summary TEXT,
            payload TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS lab_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS lab_session_commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL REFERENCES lab_sessions(id) ON DELETE CASCADE,
            port TEXT,
            command TEXT,
            status TEXT,
            output TEXT,
            parsed_json TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS lab_session_dumps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL REFERENCES lab_sessions(id) ON DELETE CASCADE,
            dump_id INTEGER NOT NULL REFERENCES rfid_card_dumps(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            UNIQUE(session_id, dump_id)
        );

        CREATE TABLE IF NOT EXISTS command_favorites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            command TEXT NOT NULL UNIQUE,
            protocol TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS command_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            port TEXT,
            command TEXT,
            status TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS card_inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uid TEXT NOT NULL UNIQUE,
            card_type TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            dump_count INTEGER NOT NULL DEFAULT 0,
            notes TEXT,
            risk_level TEXT
        );

        CREATE TABLE IF NOT EXISTS smart_scan_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            status TEXT NOT NULL,
            stage TEXT NOT NULL,
            progress INTEGER NOT NULL DEFAULT 0,
            uid TEXT,
            family TEXT,
            card_type TEXT,
            acquisition_status TEXT,
            dump_id INTEGER REFERENCES rfid_card_dumps(id) ON DELETE SET NULL,
            error TEXT,
            options_json TEXT NOT NULL DEFAULT '{}',
            result_json TEXT NOT NULL DEFAULT '{}',
            cancel_requested INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS smart_scan_steps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id INTEGER NOT NULL REFERENCES smart_scan_jobs(id) ON DELETE CASCADE,
            step_index INTEGER NOT NULL,
            stage TEXT NOT NULL,
            command TEXT NOT NULL,
            status TEXT NOT NULL,
            output TEXT,
            output_excerpt TEXT,
            parsed_json TEXT NOT NULL DEFAULT '{}',
            started_at TEXT NOT NULL,
            finished_at TEXT,
            UNIQUE(job_id, step_index)
        );

        CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
        CREATE INDEX IF NOT EXISTS idx_rfid_events_uid ON rfid_events(uid);
        CREATE INDEX IF NOT EXISTS idx_mifare_blocks_uid ON mifare_blocks(card_uid);
        CREATE INDEX IF NOT EXISTS idx_proxmark_logs_time ON proxmark_logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_pm3_versions_time ON proxmark_runtime_versions(observed_at);
        CREATE INDEX IF NOT EXISTS idx_rfid_dumps_sha ON rfid_card_dumps(sha256);
        CREATE INDEX IF NOT EXISTS idx_rfid_dumps_uid ON rfid_card_dumps(uid);
        CREATE INDEX IF NOT EXISTS idx_rfid_blocks_dump ON rfid_card_blocks(dump_id);
        CREATE INDEX IF NOT EXISTS idx_rfid_pm3_uid ON rfid_pm3_events(uid);
        CREATE INDEX IF NOT EXISTS idx_session_commands_session ON lab_session_commands(session_id);
        CREATE INDEX IF NOT EXISTS idx_smart_scan_status ON smart_scan_jobs(status, updated_at);
        CREATE INDEX IF NOT EXISTS idx_smart_scan_uid ON smart_scan_jobs(uid);
        CREATE INDEX IF NOT EXISTS idx_smart_steps_job ON smart_scan_steps(job_id, step_index);
        """
    )


def init_db() -> None:
    conn = get_connection()
    try:
        _create_schema(conn)
        existing = {row[0] for row in conn.execute("SELECT version FROM schema_migrations")}
        for version in range(1, SCHEMA_VERSION + 1):
            if version not in existing:
                conn.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (version, now_str()),
                )
        conn.commit()
    finally:
        conn.close()


def get_setting(key: str, default: str = "") -> str:
    init_db()
    conn = get_connection()
    try:
        row = conn.execute("SELECT value FROM app_settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default
    finally:
        conn.close()


def set_setting(key: str, value) -> None:
    init_db()
    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO app_settings(key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
            """,
            (key, str(value or ""), now_str()),
        )
        conn.commit()
    finally:
        conn.close()


def add_audit(actor: str, action: str, target: str = "", outcome: str = "ok", details: str = "") -> None:
    init_db()
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO audit_log(actor,action,target,outcome,details,created_at) VALUES (?,?,?,?,?,?)",
            (actor, action, target, outcome, details, now_str()),
        )
        conn.commit()
    finally:
        conn.close()
