from __future__ import annotations

import json

from app.rf.card_dump_analyzer import (
    crc8_mad,
    detect_value_block,
    parse_dump_content,
    parse_mfu_binary,
)
from app.rfid.mifare_parser import analyze_mifare_classic_dump


def type2_pages():
    uid = bytes.fromhex("04A1B2C3D4E5F6")
    bcc0 = 0x88 ^ uid[0] ^ uid[1] ^ uid[2]
    bcc1 = uid[3] ^ uid[4] ^ uid[5] ^ uid[6]
    return [bytes([uid[0], uid[1], uid[2], bcc0]), uid[3:7], bytes([bcc1, 0x48, 0x00, 0x00]), bytes.fromhex("E1101200")]


def test_mfu_new_56_byte_header_is_not_memory():
    pages = type2_pages()
    header = bytearray(56)
    header[11] = len(pages) - 1
    units, metadata = parse_mfu_binary(bytes(header) + b"".join(pages))
    assert metadata["mfu_format"] == "new-56-byte-prefix"
    assert units == [page.hex().upper() for page in pages]
    assert metadata["uid_bcc_valid"] is True


def test_mfu_old_48_byte_header_is_not_memory():
    pages = type2_pages()
    header = bytes(48)
    units, metadata = parse_mfu_binary(header + b"".join(pages))
    assert metadata["mfu_format"] == "old-48-byte-prefix"
    assert units == [page.hex().upper() for page in pages]


def test_plain_mfu_pages_are_supported():
    pages = type2_pages()
    units, metadata = parse_mfu_binary(b"".join(pages))
    assert metadata["mfu_format"] == "plain-pages"
    assert units == [page.hex().upper() for page in pages]



def test_classic_seven_byte_uid_manufacturer_bcc():
    uid = bytes.fromhex("04112233445566")
    bcc = 0
    for byte in uid:
        bcc ^= byte
    block0 = (uid + bytes([bcc]) + bytes(8)).hex().upper()
    units = [block0] + ["00" * 16 for _ in range(63)]
    for index in range(3, 64, 4):
        units[index] = "13579BDF2468FF0780692468ACE13579"
    analysis = parse_dump_content("uid7.eml", "\n".join(units).encode())
    assert analysis["uid"] == uid.hex().upper()
    assert analysis["identity_evidence"]["uid_length_bytes"] == 7
    assert analysis["identity_evidence"]["uid_bcc_valid"] is True

def test_value_block_validates_address_complements():
    value = (12345).to_bytes(4, "little", signed=True)
    inverted = bytes(byte ^ 0xFF for byte in value)
    address = 7
    valid = value + inverted + value + bytes([address, address ^ 0xFF, address, address ^ 0xFF])
    invalid = valid[:-1] + b"\x00"
    assert detect_value_block(valid.hex()) == {"value": 12345, "address": 7, "valid": True}
    assert detect_value_block(invalid.hex()) is None


def classic_dump_with_one_default_sector():
    units = []
    for index in range(64):
        if index == 0:
            uid = bytes.fromhex("A1B2C3D4")
            bcc = uid[0] ^ uid[1] ^ uid[2] ^ uid[3]
            units.append((uid + bytes([bcc]) + bytes(11)).hex().upper())
        elif index % 4 == 3:
            if index == 3:
                units.append("FFFFFFFFFFFFFF078069FFFFFFFFFFFF")
            else:
                units.append("13579BDF2468FF0780692468ACE13579")
        else:
            units.append("00" * 16)
    return units


def test_default_keys_are_counted_by_sector_not_twice():
    units = classic_dump_with_one_default_sector()
    analysis = parse_dump_content("test.eml", "\n".join(units).encode())
    assert analysis["stats"]["default_key_sectors"] == 1
    assert analysis["stats"]["default_key_blocks"] == 1
    assert analysis["stats"]["default_key_a_count"] == 1
    assert analysis["stats"]["default_key_b_count"] == 1
    assert analysis["stats"]["default_key_both_count"] == 1


def test_legacy_parser_uses_same_normalized_risk_engine():
    units = classic_dump_with_one_default_sector()
    text = "\n".join(units)
    normalized = parse_dump_content("card.eml", text.encode())
    legacy = analyze_mifare_classic_dump("A1B2C3D4", text)
    assert legacy["summary"]["risk_level"] == normalized["risk_level"]
    assert legacy["summary"]["risk_score"] == normalized["risk_score"]
    assert legacy["summary"]["default_key_sectors"] == normalized["stats"]["default_key_sectors"]


def test_mad_requires_key_gpb_and_valid_crc():
    units = classic_dump_with_one_default_sector()
    block1 = bytearray(16)
    block1[1] = 0x00
    block1[2:4] = bytes.fromhex("E103")
    block2 = bytes(16)
    block1[0] = crc8_mad(bytes(block1[1:]) + block2)
    units[1] = bytes(block1).hex().upper()
    units[2] = block2.hex().upper()
    units[3] = "A0A1A2A3A4A5FF0780C12468ACE13579"
    analysis = parse_dump_content("mad.eml", "\n".join(units).encode())
    assert analysis["mad_aid"]
    assert analysis["mad_aid"][0]["crc_valid"] is True
    assert analysis["mad_aid"][0]["aids"][0]["aid"] == "E103"


def test_mifare_plus_json_model():
    payload = {
        "FileType": "mfp v1",
        "Card": {"UID": "04112233445566", "SecurityLevel": "SL3"},
        "blocks": {str(i): "00" * 16 for i in range(64)},
    }
    analysis = parse_dump_content("plus.json", json.dumps(payload).encode())
    assert analysis["card_type"] == "MIFARE Plus SL3"
    assert analysis["metadata"]["security_level"] == "SL3"
    assert analysis["stats"]["protocol_model"] == "mifare_plus"
    assert analysis["stats"]["default_key_sectors"] == 0
    assert analysis["stats"]["invalid_access_conditions"] == 0
