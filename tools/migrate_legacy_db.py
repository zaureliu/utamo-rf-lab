#!/usr/bin/env python3
"""Import one legacy Utamo RF Lab SQLite database into the unified runtime DB.

Run against a backup and preferably with an empty target database. Primary keys
are preserved so dump/report/session relationships remain intact.
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

from app.database.db import DB_PATH, get_connection, init_db

TABLES = [
    "app_settings", "rfid_events", "mifare_blocks", "proxmark_logs", "rfid_card_dumps",
    "rfid_card_blocks", "rfid_card_reports", "rfid_dump_comparisons", "rfid_pm3_events",
    "lab_sessions", "lab_session_commands", "lab_session_dumps", "command_favorites",
    "command_history", "card_inventory",
]


def columns(conn: sqlite3.Connection, table: str) -> list[str]:
    return [row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')]


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: migrate_legacy_db.py path/to/legacy.db", file=sys.stderr)
        return 2
    source_path = Path(sys.argv[1]).expanduser().resolve()
    if not source_path.is_file():
        print(f"source not found: {source_path}", file=sys.stderr)
        return 2
    if source_path == DB_PATH:
        print("source and target are the same database", file=sys.stderr)
        return 2

    init_db()
    source = sqlite3.connect(source_path)
    source.row_factory = sqlite3.Row
    target = get_connection()
    imported = {}
    try:
        source_tables = {row[0] for row in source.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        target.execute("BEGIN IMMEDIATE")
        for table in TABLES:
            if table not in source_tables:
                continue
            source_columns = columns(source, table)
            target_columns = columns(target, table)
            mapping = {name: name for name in source_columns if name in target_columns}
            if table == "rfid_dump_comparisons":
                if "clone_score" in source_columns and "static_similarity_score" in target_columns:
                    mapping["clone_score"] = "static_similarity_score"
                if "clone_status" in source_columns and "comparison_status" in target_columns:
                    mapping["clone_status"] = "comparison_status"
            if not mapping:
                continue
            source_names = list(mapping)
            target_names = [mapping[name] for name in source_names]
            source_quoted = ",".join(f'"{name}"' for name in source_names)
            target_quoted = ",".join(f'"{name}"' for name in target_names)
            placeholders = ",".join("?" for _ in target_names)
            count = 0
            # Identifiers come only from SQLite introspection and the fixed TABLES allowlist.
            for row in source.execute(f'SELECT {source_quoted} FROM "{table}"'):  # noqa: S608
                target.execute(
                    f'INSERT OR IGNORE INTO "{table}" ({target_quoted}) VALUES ({placeholders})',  # noqa: S608
                    tuple(row[name] for name in source_names),
                )
                count += 1
            imported[table] = count
        target.commit()
    except Exception:
        target.rollback()
        raise
    finally:
        source.close()
        target.close()

    print(f"target: {DB_PATH}")
    for table, count in imported.items():
        print(f"{table}: {count} source row(s) processed")
    print("Review imported data. Legacy reports may contain unmasked UIDs or keys.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
