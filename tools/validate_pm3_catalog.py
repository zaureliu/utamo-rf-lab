#!/usr/bin/env python3
"""Validate Utamo catalog commands against a local RRG/Iceman commands.md.

Usage:
    python tools/validate_pm3_catalog.py path/to/proxmark3/doc/commands.md

The script is intentionally offline: pin/clone the desired upstream commit, then
run this validator in CI or before updating the catalog.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.rf.protocol_catalog import PROTOCOLS, normalize_command  # noqa: E402


def command_present(command: str, text: str) -> bool:
    normalized_doc = " ".join(text.lower().split())
    normalized = normalize_command(command)
    return normalized in normalized_doc or re.search(r"\b" + re.escape(normalized.replace(" ", r"\s+")) + r"\b", text, re.I) is not None


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_pm3_catalog.py path/to/proxmark3/doc/commands.md", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    if not path.is_file():
        print(f"not found: {path}", file=sys.stderr)
        return 2
    text = path.read_text(encoding="utf-8", errors="replace")
    missing = []
    for protocol in PROTOCOLS:
        for command in protocol.get("safe_commands", []) + protocol.get("blocked_examples", []):
            if not command_present(command, text):
                missing.append((protocol["id"], command))
    if missing:
        for protocol_id, command in missing:
            print(f"MISSING {protocol_id}: {command}")
        return 1
    print(f"OK: {sum(len(p.get('safe_commands', [])) + len(p.get('blocked_examples', [])) for p in PROTOCOLS)} catalog commands found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
