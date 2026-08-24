"""Small NFC Forum NDEF/TLV decoder for NTAG/Ultralight dumps."""

from __future__ import annotations

URI_PREFIX = {
    0x00: "", 0x01: "http://www.", 0x02: "https://www.", 0x03: "http://", 0x04: "https://",
    0x05: "tel:", 0x06: "mailto:", 0x07: "ftp://anonymous:anonymous@", 0x08: "ftp://ftp.",
    0x09: "ftps://", 0x0A: "sftp://", 0x0B: "smb://", 0x0C: "nfs://", 0x0D: "ftp://",
    0x0E: "dav://", 0x0F: "news:", 0x10: "telnet://", 0x11: "imap:", 0x12: "rtsp://",
    0x13: "urn:", 0x14: "pop:", 0x15: "sip:", 0x16: "sips:", 0x17: "tftp:",
    0x18: "btspp://", 0x19: "btl2cap://", 0x1A: "btgoep://", 0x1B: "tcpobex://",
    0x1C: "irdaobex://", 0x1D: "file://", 0x1E: "urn:epc:id:", 0x1F: "urn:epc:tag:",
    0x20: "urn:epc:pat:", 0x21: "urn:epc:raw:", 0x22: "urn:epc:", 0x23: "urn:nfc:",
}

TNF_NAMES = {
    0: "Empty", 1: "NFC Well Known", 2: "MIME Media", 3: "Absolute URI",
    4: "External", 5: "Unknown", 6: "Unchanged", 7: "Reserved",
}


def clean_hex(text: str) -> str:
    return "".join(ch for ch in str(text or "").upper() if ch in "0123456789ABCDEF")


def pages_to_memory_bytes(units):
    data = bytearray()
    for unit in units or []:
        hx = clean_hex(unit)
        if len(hx) >= 8:
            data.extend(bytes.fromhex(hx[:8]))
        elif len(hx) >= 2:
            data.extend(bytes.fromhex(hx[: len(hx) - (len(hx) % 2)]))
    return bytes(data)


def parse_tlvs(memory: bytes):
    tlvs = []
    i = 0
    ndef_payloads = []
    while i < len(memory):
        t = memory[i]
        i += 1
        if t == 0x00:
            continue
        if t == 0xFE:
            tlvs.append({"type": "terminator", "offset": i - 1})
            break
        if i >= len(memory):
            break
        length = memory[i]
        i += 1
        if length == 0xFF and i + 2 <= len(memory):
            length = int.from_bytes(memory[i:i+2], "big")
            i += 2
        value = memory[i:i+length]
        i += length
        label = {0x01: "Lock Control", 0x02: "Memory Control", 0x03: "NDEF Message", 0xFD: "Proprietary"}.get(t, f"TLV 0x{t:02X}")
        item = {"type": label, "tag": f"0x{t:02X}", "length": length, "value_hex": value.hex().upper()}
        tlvs.append(item)
        if t == 0x03:
            ndef_payloads.append(value)
    return tlvs, ndef_payloads


def decode_record_payload(tnf, rtype: bytes, payload: bytes):
    type_text = rtype.decode("ascii", errors="replace") if rtype else ""
    base = {"type": type_text, "payload_hex": payload.hex().upper()}
    if tnf == 1 and rtype == b"U" and payload:
        prefix = URI_PREFIX.get(payload[0], "")
        uri = prefix + payload[1:].decode("utf-8", errors="replace")
        base.update({"record_kind": "URI", "uri": uri})
    elif tnf == 1 and rtype == b"T" and payload:
        status = payload[0]
        lang_len = status & 0x3F
        encoding = "utf-16" if (status & 0x80) else "utf-8"
        language = payload[1:1+lang_len].decode("ascii", errors="replace")
        text = payload[1+lang_len:].decode(encoding, errors="replace")
        base.update({"record_kind": "TEXT", "language": language, "text": text})
    elif tnf == 2:
        base.update({"record_kind": "MIME", "mime_type": type_text})
    elif tnf == 3:
        base.update({"record_kind": "ABSOLUTE_URI", "uri": payload.decode("utf-8", errors="replace")})
    else:
        base.update({"record_kind": TNF_NAMES.get(tnf, "Unknown")})
    return base


def parse_ndef_message(data: bytes):
    records = []
    i = 0
    while i < len(data):
        header = data[i]
        i += 1
        mb = bool(header & 0x80)
        me = bool(header & 0x40)
        cf = bool(header & 0x20)
        sr = bool(header & 0x10)
        il = bool(header & 0x08)
        tnf = header & 0x07
        if i >= len(data):
            break
        type_len = data[i]
        i += 1
        if sr:
            if i >= len(data):
                break
            payload_len = data[i]
            i += 1
        else:
            if i + 4 > len(data):
                break
            payload_len = int.from_bytes(data[i:i+4], "big")
            i += 4
        id_len = 0
        if il:
            if i >= len(data):
                break
            id_len = data[i]
            i += 1
        rtype = data[i:i+type_len]
        i += type_len
        rid = data[i:i+id_len]
        i += id_len
        payload = data[i:i+payload_len]
        i += payload_len
        decoded = decode_record_payload(tnf, rtype, payload)
        decoded.update({
            "mb": mb, "me": me, "cf": cf, "sr": sr, "il": il, "tnf": tnf,
            "tnf_name": TNF_NAMES.get(tnf, "Unknown"), "id_hex": rid.hex().upper(),
        })
        records.append(decoded)
        if me:
            break
    return records


def decode_ndef_from_units(units):
    memory = pages_to_memory_bytes(units)
    # NTAG/Ultralight user memory normally starts at page 4. Try full memory and user memory.
    candidates = [memory]
    if len(memory) > 16:
        candidates.append(memory[16:])
    best = {"found": False, "tlvs": [], "records": []}
    for candidate in candidates:
        tlvs, payloads = parse_tlvs(candidate)
        records = []
        for payload in payloads:
            records.extend(parse_ndef_message(payload))
        if records or any(t.get("type") == "NDEF Message" for t in tlvs):
            return {"found": True, "tlvs": tlvs, "records": records}
        if tlvs:
            best = {"found": False, "tlvs": tlvs, "records": []}
    return best
