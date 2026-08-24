KNOWN_DEVICES = {
    ("9AC4", "4B8F"): {
        "device_type": "Proxmark3 Easy",
        "family": "RFID/NFC",
        "driver": "USB CDC",
        "confidence": "HIGH",
        "notes": "VID/PID compatível com Proxmark3 Iceman"
    },
    ("2D2D", "504D"): {
        "device_type": "Proxmark3",
        "family": "RFID/NFC",
        "driver": "USB CDC",
        "confidence": "HIGH",
        "notes": "Possível Proxmark3 por VID/PID"
    },
    ("10C4", "EA60"): {
        "device_type": "USB Serial / CP210x",
        "family": "Serial",
        "driver": "CP210x",
        "confidence": "MEDIUM",
        "notes": "Pode ser usado por bridges seriais; validar manualmente"
    },
    ("1A86", "7523"): {
        "device_type": "USB Serial / CH340",
        "family": "Serial",
        "driver": "CH340",
        "confidence": "MEDIUM",
        "notes": "Conversor USB-Serial genérico"
    },
}


def hex_or_none(value):
    if value is None:
        return None
    return f"{value:04X}"


def _get(obj, name, default=None):
    try:
        return getattr(obj, name, default)
    except Exception:
        return default


def identify_device(port):
    vid = hex_or_none(_get(port, "vid"))
    pid = hex_or_none(_get(port, "pid"))
    if vid and pid and (vid, pid) in KNOWN_DEVICES:
        return KNOWN_DEVICES[(vid, pid)]

    blob = " ".join(str(_get(port, field, "") or "") for field in [
        "device", "name", "description", "manufacturer", "hwid", "serial_number", "product", "interface"
    ]).lower()

    if "proxmark" in blob or "iceman" in blob or "pm3" in blob:
        return {
            "device_type": "Proxmark3",
            "family": "RFID/NFC",
            "driver": "USB CDC",
            "confidence": "HIGH",
            "notes": "Identificado por descrição/serial Proxmark/Iceman"
        }
    if "usb serial" in blob or "cp210" in blob or "ch340" in blob or "ftdi" in blob:
        return {
            "device_type": "USB Serial",
            "family": "Serial",
            "driver": "USB Serial",
            "confidence": "LOW",
            "notes": "Porta serial detectada; pode ser Proxmark3 se o cliente PM3 conseguir conectar"
        }
    return {
        "device_type": "Unknown",
        "family": "Unknown",
        "driver": "Unknown",
        "confidence": "LOW",
        "notes": "Porta serial não identificada"
    }


def scan_com_ports():
    try:
        import serial.tools.list_ports
        ports = serial.tools.list_ports.comports()
    except Exception as exc:
        return [{
            "device": "",
            "name": "pyserial indisponível",
            "description": str(exc),
            "manufacturer": "",
            "hwid": "",
            "vid": None,
            "pid": None,
            "vid_pid": None,
            "serial_number": "",
            "location": "",
            "product": "",
            "interface": "",
            "device_type": "Dependency missing",
            "family": "Runtime",
            "driver": "pyserial",
            "confidence": "LOW",
            "notes": "Instale pyserial: pip install pyserial"
        }]

    results = []
    for port in ports:
        identity = identify_device(port)
        vid = hex_or_none(_get(port, "vid"))
        pid = hex_or_none(_get(port, "pid"))
        results.append({
            "device": _get(port, "device", ""),
            "name": _get(port, "name", ""),
            "description": _get(port, "description", ""),
            "manufacturer": _get(port, "manufacturer", ""),
            "hwid": _get(port, "hwid", ""),
            "vid": vid,
            "pid": pid,
            "vid_pid": f"{vid}:{pid}" if vid and pid else None,
            "serial_number": _get(port, "serial_number", ""),
            "location": _get(port, "location", ""),
            "product": _get(port, "product", ""),
            "interface": _get(port, "interface", ""),
            **identity,
        })
    return results
