from __future__ import annotations

import json

from app.rf.card_dump_analyzer import get_latest_report, ingest_card_dump
from app.rf.report_exporter import export_report_json


def make_dump() -> bytes:
    units = []
    for index in range(64):
        if index == 0:
            uid = bytes.fromhex("A1B2C3D4")
            units.append((uid + bytes([uid[0] ^ uid[1] ^ uid[2] ^ uid[3]]) + bytes(11)).hex().upper())
        elif index % 4 == 3:
            units.append("FFFFFFFFFFFFFF078069FFFFFFFFFFFF" if index == 3 else "13579BDF2468FF0780692468ACE13579")
        else:
            units.append("00" * 16)
    return "\n".join(units).encode()


def test_reports_mask_keys_by_default():
    result = ingest_card_dump("mask.eml", make_dump(), "mask-test")
    report = get_latest_report(result["dump_id"])
    trailer = next(block for block in report["blocks"] if block["is_trailer"])
    assert "•" in trailer["key_a"]
    assert "FFFFFFFFFFFF" not in trailer["block_hex"]
    assert "•" in report["statistics"]["sector_profiles"]["0"]["key_a"]
    path = export_report_json(result["dump_id"])
    exported = json.loads(path.read_text(encoding="utf-8"))
    exported_trailer = next(block for block in exported["blocks"] if block["is_trailer"])
    assert exported["export_policy"]["keys_masked"] is True
    assert exported_trailer["key_a"] != "FFFFFFFFFFFF"
    assert "FFFFFFFFFFFF" not in exported_trailer["block_hex"]
