"""MIFARE Classic Access Conditions decoder.

Decodifica os bytes 6, 7 e 8 do trailer do setor e valida os bits
complementares C1/C2/C3. A saída é orientada para laboratório: mostra a
tripla por bloco, validade e permissões interpretadas.
"""

from __future__ import annotations


def _clean_hex(value: str) -> str:
    return "".join(ch for ch in str(value or "").upper() if ch in "0123456789ABCDEF")


DATA_PERMISSIONS = {
    "000": {
        "read": "Key A ou Key B", "write": "Key A ou Key B", "increment": "Key A ou Key B", "decrement_transfer_restore": "Key A ou Key B",
        "label": "Transporte/default: leitura e escrita abertas com chaves do setor.",
    },
    "010": {
        "read": "Key A ou Key B", "write": "Nunca", "increment": "Nunca", "decrement_transfer_restore": "Key A ou Key B",
        "label": "Bloco de valor com débito/restauração permitidos.",
    },
    "100": {
        "read": "Key A ou Key B", "write": "Key B", "increment": "Nunca", "decrement_transfer_restore": "Nunca",
        "label": "Dados legíveis; escrita restrita à Key B.",
    },
    "110": {
        "read": "Key A ou Key B", "write": "Key B", "increment": "Key B", "decrement_transfer_restore": "Key A ou Key B",
        "label": "Bloco de valor com operações separadas por Key B.",
    },
    "001": {
        "read": "Key A ou Key B", "write": "Nunca", "increment": "Nunca", "decrement_transfer_restore": "Nunca",
        "label": "Somente leitura para dados.",
    },
    "011": {
        "read": "Key B", "write": "Key B", "increment": "Nunca", "decrement_transfer_restore": "Nunca",
        "label": "Leitura/escrita de dados somente com Key B.",
    },
    "101": {
        "read": "Key B", "write": "Nunca", "increment": "Nunca", "decrement_transfer_restore": "Nunca",
        "label": "Leitura somente com Key B.",
    },
    "111": {
        "read": "Nunca", "write": "Nunca", "increment": "Nunca", "decrement_transfer_restore": "Nunca",
        "label": "Bloco inacessível pela matriz de acesso.",
    },
}

TRAILER_PERMISSIONS = {
    "000": {"key_a_read": "Nunca", "key_a_write": "Key A", "access_read": "Key A", "access_write": "Key A", "key_b_read": "Key A", "key_b_write": "Key A", "label": "Trailer em transporte/default."},
    "010": {"key_a_read": "Nunca", "key_a_write": "Nunca", "access_read": "Key A", "access_write": "Nunca", "key_b_read": "Key A", "key_b_write": "Nunca", "label": "Trailer travado para escrita."},
    "100": {"key_a_read": "Nunca", "key_a_write": "Key B", "access_read": "Key A ou Key B", "access_write": "Key B", "key_b_read": "Nunca", "key_b_write": "Key B", "label": "Administração por Key B."},
    "110": {"key_a_read": "Nunca", "key_a_write": "Nunca", "access_read": "Key A ou Key B", "access_write": "Nunca", "key_b_read": "Nunca", "key_b_write": "Nunca", "label": "Trailer somente leitura para bits de acesso."},
    "001": {"key_a_read": "Nunca", "key_a_write": "Key A", "access_read": "Key A ou Key B", "access_write": "Key A", "key_b_read": "Key A ou Key B", "key_b_write": "Key A", "label": "Key B pode ser lida como dado."},
    "011": {"key_a_read": "Nunca", "key_a_write": "Key B", "access_read": "Key A ou Key B", "access_write": "Key B", "key_b_read": "Nunca", "key_b_write": "Key B", "label": "Trailer administrado por Key B."},
    "101": {"key_a_read": "Nunca", "key_a_write": "Nunca", "access_read": "Key A ou Key B", "access_write": "Nunca", "key_b_read": "Key A ou Key B", "key_b_write": "Nunca", "label": "Key B legível como dado; sem escrita."},
    "111": {"key_a_read": "Nunca", "key_a_write": "Nunca", "access_read": "Key A ou Key B", "access_write": "Nunca", "key_b_read": "Nunca", "key_b_write": "Nunca", "label": "Trailer bloqueado para escrita."},
}


def decode_access_conditions(access_hex: str) -> dict:
    """Decode 3 or 4 access bytes. Expects bytes 6-9 from a trailer, e.g. FF078069.

    Returns: {valid, bytes, blocks:[...], gpb, errors}.
    """
    hx = _clean_hex(access_hex)
    if len(hx) < 6:
        return {"valid": False, "raw": hx, "error": "Access bits incompletos", "blocks": []}
    hx = hx[:8].ljust(8, "0")
    b6 = int(hx[0:2], 16)
    b7 = int(hx[2:4], 16)
    b8 = int(hx[4:6], 16)
    gpb = hx[6:8]

    inv_c2 = (b6 >> 4) & 0x0F
    inv_c1 = b6 & 0x0F
    c1 = (b7 >> 4) & 0x0F
    inv_c3 = b7 & 0x0F
    c3 = (b8 >> 4) & 0x0F
    c2 = b8 & 0x0F

    errors: list[str] = []
    if ((c1 ^ inv_c1) & 0x0F) != 0x0F:
        errors.append("C1 não confere com complemento")
    if ((c2 ^ inv_c2) & 0x0F) != 0x0F:
        errors.append("C2 não confere com complemento")
    if ((c3 ^ inv_c3) & 0x0F) != 0x0F:
        errors.append("C3 não confere com complemento")

    blocks = []
    for block in range(4):
        triplet = f"{(c1 >> block) & 1}{(c2 >> block) & 1}{(c3 >> block) & 1}"
        is_trailer = block == 3
        perms = TRAILER_PERMISSIONS.get(triplet, {}) if is_trailer else DATA_PERMISSIONS.get(triplet, {})
        blocks.append({
            "block_in_sector": block,
            "type": "trailer" if is_trailer else "data",
            "c1": (c1 >> block) & 1,
            "c2": (c2 >> block) & 1,
            "c3": (c3 >> block) & 1,
            "condition": triplet,
            "permissions": perms,
        })

    return {
        "valid": not errors,
        "raw": hx,
        "bytes": {"b6": hx[0:2], "b7": hx[2:4], "b8": hx[4:6], "gpb": gpb},
        "nibbles": {"c1": c1, "c2": c2, "c3": c3, "inv_c1": inv_c1, "inv_c2": inv_c2, "inv_c3": inv_c3},
        "errors": errors,
        "gpb": gpb,
        "blocks": blocks,
    }


def decode_sector_trailer(trailer_hex: str) -> dict:
    hx = _clean_hex(trailer_hex).ljust(32, "0")[:32]
    return {
        "key_a": hx[0:12],
        "access_bits": hx[12:20],
        "key_b": hx[20:32],
        "decoded_access": decode_access_conditions(hx[12:20]),
    }
