"""Compatibility layer for the former MIFARE Classic parser.

All parsing and risk decisions now come from ``app.rf.card_dump_analyzer``.
This module only adapts the normalized model to the legacy UI/database shape.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from app.rf.card_dump_analyzer import (
    ascii_preview,
    clean_hex,
    detect_value_block,
    is_trailer_block,
    parse_dump_content,
    sector_for_block,
)


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _legacy_block(card_uid: str, block: dict[str, Any]) -> dict[str, Any]:
    return {
        "card_uid": card_uid,
        "sector": int(block.get("sector", 0)),
        "block": int(block.get("absolute_block", 0)),
        "block_type": "trailer" if block.get("is_trailer") else ("manufacturer" if block.get("absolute_block") == 0 else "data"),
        "data_hex": clean_hex(block.get("block_hex")),
        "ascii_preview": block.get("ascii") or ascii_preview(block.get("block_hex", "")),
        "key_a": clean_hex(block.get("key_a")),
        "access_bits": clean_hex(block.get("access_bits")),
        "key_b": clean_hex(block.get("key_b")),
        "annotations": block.get("annotations", []),
        "timestamp": now_str(),
    }


def analyze_mifare_classic_dump(card_uid: str, dump_text: str) -> dict[str, Any]:
    analysis = parse_dump_content(f"{card_uid or 'mifare-card'}.eml", str(dump_text or "").encode("utf-8"))
    if analysis.get("stats", {}).get("unit_size") != 16:
        raise ValueError("O conteúdo não foi reconhecido como dump MIFARE Classic/Plus em blocos de 16 bytes.")

    blocks = [_legacy_block(card_uid, block) for block in analysis.get("block_analysis", [])]
    summary = {
        "card_uid": card_uid,
        "card_type": analysis.get("card_type"),
        "memory_size": f"{analysis.get('block_count', 0) * 16} bytes",
        "total_blocks": analysis.get("block_count", 0),
        "total_sectors": analysis.get("sector_count", 0),
        "trailer_blocks": analysis.get("stats", {}).get("trailer_blocks", 0),
        "default_key_sectors": analysis.get("stats", {}).get("default_key_sectors", 0),
        "readable_blocks": analysis.get("stats", {}).get("ascii_blocks", 0),
        "risk_level": analysis.get("risk_level"),
        "risk_score": analysis.get("risk_score"),
        "risk_reasons": analysis.get("risk_reasons", []),
        "security_evidence": analysis.get("security_evidence", {}),
    }
    return {"summary": summary, "blocks": blocks, "risk": analysis.get("security_evidence", {}), "normalized": analysis}


def parse_mifare_classic_dump(card_uid: str, dump_text: str) -> dict[str, Any]:
    return analyze_mifare_classic_dump(card_uid, dump_text)


# Small compatibility helpers retained for integrations that imported them.
def classify_card_type(total_blocks: int) -> dict[str, Any]:
    labels = {20: ("MIFARE Mini", 5), 64: ("MIFARE Classic 1K", 16), 128: ("MIFARE Classic 2K", 32), 256: ("MIFARE Classic 4K", 40)}
    card_type, sectors = labels.get(int(total_blocks), ("Unknown 16-byte block dump", 0))
    return {"card_type": card_type, "memory_size": f"{int(total_blocks) * 16} bytes", "expected_blocks": int(total_blocks), "expected_sectors": sectors}


def get_sector_from_block(block_number: int) -> int:
    return sector_for_block(int(block_number))


def classify_block(block_number: int) -> str:
    number = int(block_number)
    if number == 0:
        return "manufacturer"
    return "trailer" if is_trailer_block(number) else "data"


def classify_block_content(data_hex: str, block_type: str = "data") -> dict[str, Any]:
    hx = clean_hex(data_hex)
    if len(hx) != 32:
        return {"content_type": "invalid_size", "content_label": "Tamanho inválido", "content_flags": "invalid"}
    if hx in {"00" * 16, "FF" * 16}:
        return {"content_type": "empty_block", "content_label": "Bloco vazio/padrão", "content_flags": "empty"}
    if block_type == "trailer":
        return {"content_type": "sector_trailer", "content_label": "Sector Trailer", "content_flags": "access_control"}
    if detect_value_block(hx):
        return {"content_type": "value_block", "content_label": "Value Block válido", "content_flags": "value"}
    preview = ascii_preview(hx)
    if sum(ch != "." for ch in preview) >= 4:
        return {"content_type": "ascii_data", "content_label": "Dados com texto legível", "content_flags": "readable"}
    return {"content_type": "binary_data", "content_label": "Dados binários", "content_flags": "binary"}
