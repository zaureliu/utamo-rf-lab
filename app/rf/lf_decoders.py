"""LF/Wiegand helper decoders for lab reports."""

from __future__ import annotations


def clean_bits(value: str) -> str:
    return "".join(ch for ch in str(value or "") if ch in "01")


def clean_hex(value: str) -> str:
    return "".join(ch for ch in str(value or "").upper() if ch in "0123456789ABCDEF")


def decode_wiegand(bits: str):
    b = clean_bits(bits)
    result = {"bits": b, "bit_length": len(b), "recognized": False}
    if len(b) == 26:
        facility = int(b[1:9], 2)
        card = int(b[9:25], 2)
        even = b[0]
        odd = b[25]
        even_calc = str(b[1:13].count("1") % 2)
        odd_calc = str(0 if b[13:25].count("1") % 2 else 1)
        result.update({
            "recognized": True,
            "format": "Wiegand 26",
            "facility_code": facility,
            "card_number": card,
            "parity": {"even_bit": even, "even_expected": even_calc, "odd_bit": odd, "odd_expected": odd_calc, "valid_hint": even == even_calc and odd == odd_calc},
        })
    elif len(b) == 34:
        result.update({
            "recognized": True,
            "format": "Wiegand 34",
            "facility_code": int(b[1:17], 2),
            "card_number": int(b[17:33], 2),
        })
    elif len(b) == 35:
        result.update({
            "recognized": True,
            "format": "HID Corporate 1000 style 35-bit candidate",
            "company_code": int(b[2:14], 2),
            "card_number": int(b[14:34], 2),
        })
    elif len(b) == 37:
        result.update({
            "recognized": True,
            "format": "HID 37-bit candidate",
            "card_number": int(b[1:36], 2),
        })
    return result


def decode_em410x(hex_value: str):
    hx = clean_hex(hex_value)
    if len(hx) < 10:
        return {"recognized": False, "raw_hex": hx}
    # EM410x commonly displayed as 5 bytes / 10 hex chars.
    hx = hx[-10:]
    return {
        "recognized": True,
        "format": "EM410x/EM-Marin 40-bit candidate",
        "raw_hex": hx,
        "decimal": int(hx, 16),
        "facility_hint": int(hx[0:2], 16),
        "card_number_hint": int(hx[2:], 16),
    }
