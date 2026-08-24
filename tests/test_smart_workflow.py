from __future__ import annotations

import json
from pathlib import Path

from app import create_app
from app.rf.protocol_catalog import classify_smart_acquisition_command
from app.rf.smart_workflow import (
    build_command_plan,
    create_smart_scan,
    extract_card_facts,
    get_smart_scan,
    recover_interrupted_smart_scans,
    run_smart_scan,
    smart_scan_public_payload,
)


def test_search_parser_ignores_probe_lines_and_classifies_classic():
    output = """
[=] ---------- ISO14443-A Information ----------
[+] UID: C0 EC 19 5F
[+] ATQA: 00 04
[+] SAK: 08
[-] Searching for MIFARE Ultralight tag...
[-] Searching for DESFire tag...
"""
    facts = extract_card_facts(output)
    assert facts["family"] == "MIFARE_CLASSIC"
    assert facts["uid"] == "C0EC195F"
    assert facts["atqa"] == "0004"
    assert facts["sak"] == "08"


def test_card_size_recognizes_common_classic_labels():
    facts = extract_card_facts("MIFARE Classic 4K\nUID: A1 B2 C3 D4\nSAK: 18")
    assert facts["family"] == "MIFARE_CLASSIC"
    assert facts["card_size"] == "4k"


def test_plans_are_family_specific_and_read_only():
    classic = build_command_plan(
        {"family": "MIFARE_CLASSIC", "card_size": "1k"},
        7,
        {"auto_dump": True, "read_ndef": True, "mfc_key_basename": "mfc-keys.bin"},
    )
    commands = [step.command for step in classic]
    assert commands == [
        "hf mf info",
        "hf mf ndefread",
        "hf mf dump --1k -f utamo-smart-7-mfc -k mfc-keys.bin",
    ]
    forbidden = ("autopwn", "nested", "hardnested", "write", "wrbl", "sim", "restore", "wipe")
    assert not any(word in command for command in commands for word in forbidden)

    desfire = [step.command for step in build_command_plan(
        {"family": "MIFARE_DESFIRE"}, 8, {"auto_dump": True, "read_ndef": True}
    )]
    assert desfire == [
        "hf mfdes info",
        "hf mfdes getversion",
        "hf mfdes getuid",
        "hf mfdes freemem",
        "hf mfdes getaids",
        "hf mfdes lsapp",
    ]


def test_internal_acquisition_policy_allows_only_safe_basenames():
    assert classify_smart_acquisition_command("hf mfu dump -f utamo-smart-9-mfu -z")["allowed"] is True
    assert classify_smart_acquisition_command("hf mf dump --1k -f card -k mfc-keys.bin")["allowed"] is True
    assert classify_smart_acquisition_command("hf mfu dump -f ../outside -z")["allowed"] is False
    assert classify_smart_acquisition_command("hf mf wrbl --blk 1 -d 0000")["allowed"] is False
    assert classify_smart_acquisition_command("hf mf autopwn")["allowed"] is False


def _type2_pages():
    uid = bytes.fromhex("04A1B2C3D4E5F6")
    bcc0 = 0x88 ^ uid[0] ^ uid[1] ^ uid[2]
    bcc1 = uid[3] ^ uid[4] ^ uid[5] ^ uid[6]
    return [
        bytes([uid[0], uid[1], uid[2], bcc0]).hex().upper(),
        uid[3:7].hex().upper(),
        bytes([bcc1, 0x48, 0x00, 0x00]).hex().upper(),
        "E1101200",
    ]


def test_full_smart_mfu_flow_imports_generated_dump(tmp_path, monkeypatch):
    app = create_app({
        "TESTING": True,
        "SMART_SCAN_DIR": tmp_path / "smart-scans",
        "SMART_SCAN_MAX_COMMANDS": 12,
        "SMART_SCAN_TOTAL_TIMEOUT": 120,
    })

    monkeypatch.setattr("app.rf.smart_workflow.get_setting", lambda key, default="": {
        "proxmark_client_path": str(tmp_path / "proxmark3.exe"),
        "proxmark_port": "COM3",
        "mfc_key_file": "",
    }.get(key, default))

    outputs = {
        "hf search": "ISO14443-A Information\nUID: 04 A1 B2 C3 D4 E5 F6\nATQA: 00 44\nSAK: 00\nMIFARE Ultralight / NTAG",
        "hf mfu info": "MIFARE Ultralight EV1\nUID: 04 A1 B2 C3 D4 E5 F6",
        "hf mfu ndefread": "NDEF Message\nURI: https://example.invalid",
    }

    def fake_executor(_client, command, port, **kwargs):
        workspace = Path(kwargs["working_directory"])
        if command.startswith("hf mfu dump"):
            payload = {
                "FileType": "mfu v3",
                "Card": {"UID": "04A1B2C3D4E5F6"},
                "pages": _type2_pages(),
            }
            (workspace / "utamo-smart-test.json").write_text(json.dumps(payload), encoding="utf-8")
            output = "MIFARE Ultralight EV1\nUID: 04 A1 B2 C3 D4 E5 F6\nSaved JSON dump"
        else:
            output = outputs[command]
        return {
            "status": "ok",
            "output": output,
            "logs": [{"port": port, "command": command, "status": "OK", "output": output, "timestamp": "2026-07-19 21:00:00"}],
        }

    with app.app_context():
        job_id = create_smart_scan({"auto_dump": True, "read_ndef": True, "enforce_uid": True})
        result = run_smart_scan(job_id, executor=fake_executor)

    assert result["status"] == "completed"
    assert result["family"] == "MIFARE_ULTRALIGHT"
    assert result["uid"] == "04A1B2C3D4E5F6"
    assert result["dump_id"]
    assert result["acquisition_status"] == "dump_acquired"
    assert [step["command"] for step in result["steps"]] == [
        "hf search",
        "hf mfu info",
        "hf mfu ndefread",
        f"hf mfu dump -f utamo-smart-{job_id}-mfu -z",
    ]


def test_uid_change_aborts_workflow(tmp_path, monkeypatch):
    app = create_app({"TESTING": True, "SMART_SCAN_DIR": tmp_path / "smart-scans"})
    monkeypatch.setattr("app.rf.smart_workflow.get_setting", lambda key, default="": {
        "proxmark_client_path": str(tmp_path / "proxmark3.exe"),
        "proxmark_port": "COM3",
        "mfc_key_file": "",
    }.get(key, default))

    def fake_executor(_client, command, port, **kwargs):
        output = (
            "MIFARE Classic 1K\nUID: A1 B2 C3 D4\nATQA: 00 04\nSAK: 08"
            if command == "hf search"
            else "MIFARE Classic 1K\nUID: 11 22 33 44\nSAK: 08"
        )
        return {"status": "ok", "output": output, "logs": []}

    with app.app_context():
        job_id = create_smart_scan({"auto_dump": False, "read_ndef": False, "enforce_uid": True})
        result = run_smart_scan(job_id, executor=fake_executor)

    assert result["status"] == "failed"
    assert "trocado" in result["error"] or "mudou" in result["error"]


def test_public_payload_hides_local_paths():
    payload = smart_scan_public_payload({
        "id": 1,
        "options": {"mfc_key_file": r"C:\\private\\keys.bin", "mfc_key_basename": "mfc-keys.bin", "port": "COM3"},
        "result": {"workspace": r"C:\\private\\scan", "facts": {"family": "MIFARE_CLASSIC"}},
    })
    assert "mfc_key_file" not in payload["options"]
    assert "mfc_key_basename" not in payload["options"]
    assert payload["options"]["port"] == "COM3"
    assert "workspace" not in payload["result"]


def test_startup_recovery_closes_non_terminal_jobs():
    job_id = create_smart_scan({"auto_dump": True})
    assert get_smart_scan(job_id)["status"] == "queued"
    assert recover_interrupted_smart_scans() >= 1
    recovered = get_smart_scan(job_id)
    assert recovered["status"] == "failed"
    assert recovered["stage"] == "interrupted"
