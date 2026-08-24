"""Versioned Proxmark3/Iceman protocol catalog for authorized RFID analysis.

The default guard is ANALYSIS_ONLY. Advanced commands remain documented for
operator awareness, but execution policy is enforced by the Proxmark3 runner.
"""

from __future__ import annotations

import re
from copy import deepcopy

PROTOCOLS: list[dict] = [
    {
        "id": "hw_pm3",
        "family": "Hardware",
        "band": "PM3",
        "name": "Proxmark3 / Iceman Runtime",
        "standard": "RRG/Iceman hw",
        "frequency": "USB/Serial",
        "risk": "LOW",
        "description": "Validação do cliente Proxmark3, firmware, status e antenas HF/LF.",
        "safe_commands": ["hw version", "hw status", "hw tune", "hw ping"],
        "blocked_examples": ["hw bootloader", "hw reset", "hw readmem", "hw standalone"],
        "artifacts": ["runtime status", "firmware/client version", "antenna tune"],
        "parser_hints": ["client", "bootrom", "os", "baudrate", "voltage", "antenna"],
        "workflow": ["Conectar PM3", "Executar hw version", "Executar hw status", "Executar hw tune"],
    },
    {
        "id": "hf_search",
        "family": "HF",
        "band": "13.56 MHz",
        "name": "HF Search / Auto Identify",
        "standard": "RRG/Iceman hf search",
        "frequency": "13.56 MHz",
        "risk": "LOW",
        "description": "Busca geral por tags HF e sugestão de protocolo detectado.",
        "safe_commands": ["hf search"],
        "blocked_examples": ["hf sniff", "hf 14a raw"],
        "artifacts": ["UID/CSN", "ATQA/SAK", "ATS", "tag hints"],
        "parser_hints": ["iso14443-a", "iso14443-b", "iso15693", "mifare", "felica", "ntag"],
        "workflow": ["Aproximar tag HF", "Executar hf search", "Abrir protocolo sugerido", "Executar info específica"],
    },
    {
        "id": "hf_14a",
        "family": "HF",
        "band": "13.56 MHz",
        "name": "ISO14443-A",
        "standard": "ISO/IEC 14443-A",
        "frequency": "13.56 MHz",
        "risk": "LOW",
        "description": "Base de cartões MIFARE, NTAG, DESFire, passaportes, smartcards Type A e NFC Type 2/4A.",
        "safe_commands": ["hf 14a info", "hf 14a ndefread"],
        "blocked_examples": ["hf 14a sim", "hf 14a sniff", "hf 14a raw", "hf 14a apdufind", "hf 14a ndefformat", "hf 14a ndefwrite"],
        "artifacts": ["UID", "ATQA", "SAK", "ATS", "cascade level"],
        "parser_hints": ["uid", "atqa", "sak", "ats", "iso14443-a", "cascade"],
        "workflow": ["hf search", "hf 14a info", "classificar SAK/ATQA", "registrar UID e ATS"],
    },
    {
        "id": "hf_14b",
        "family": "HF",
        "band": "13.56 MHz",
        "name": "ISO14443-B / ST SRx",
        "standard": "ISO/IEC 14443-B",
        "frequency": "13.56 MHz",
        "risk": "LOW",
        "description": "Tags ISO14443-B, ST25TB/SRI/SRIX e derivados.",
        "safe_commands": ["hf 14b info"],
        "blocked_examples": ["hf 14b restore", "hf 14b sim", "hf 14b sniff", "hf 14b wrbl", "hf 14b tearoff", "hf 14b setuid"],
        "artifacts": ["ATQB", "PUPI", "application data", "protocol info"],
        "parser_hints": ["atqb", "pupi", "iso14443-b", "sri", "srix", "st25tb"],
        "workflow": ["hf search", "hf 14b info", "registrar ATQB/PUPI", "documentar fabricante"],
    },
    {
        "id": "hf_15",
        "family": "HF",
        "band": "13.56 MHz",
        "name": "ISO15693 / Vicinity",
        "standard": "ISO/IEC 15693",
        "frequency": "13.56 MHz",
        "risk": "LOW",
        "description": "Tags de longo alcance relativo: inventário, biblioteca, logística, ICODE/SLIX/ST25DV.",
        "safe_commands": ["hf 15 info"],
        "blocked_examples": ["hf 15 dump", "hf 15 sniff", "hf 15 raw", "hf 15 restore", "hf 15 wipe", "hf 15 wrbl", "hf 15 sim", "hf 15 findafi", "hf 15 writeafi", "hf 15 writedsfid"],
        "artifacts": ["UID", "DSFID", "AFI", "block size", "IC reference"],
        "parser_hints": ["iso15693", "dsfid", "afi", "ic reference", "slix", "icode"],
        "workflow": ["hf search", "hf 15 info", "registrar UID/AFI/DSFID", "classificar tag"],
    },
    {
        "id": "hf_mf",
        "family": "HF",
        "band": "13.56 MHz",
        "name": "MIFARE Classic",
        "standard": "NXP MIFARE Classic / Crypto1",
        "frequency": "13.56 MHz",
        "risk": "HIGH",
        "description": "Análise estrutural de Classic 1K/2K/4K: UID, ATQA/SAK, trailers, access bits e dumps autorizados.",
        "safe_commands": ["hf mf info", "hf mf ndefread", "hf mf dump"],
        "blocked_examples": ["hf mf autopwn", "hf mf nested", "hf mf hardnested", "hf mf darkside", "hf mf chk", "hf mf fchk", "hf mf restore", "hf mf wipe", "hf mf wrbl", "hf mf sim"],
        "artifacts": ["UID", "SAK/ATQA", "sector trailer", "Key A/B", "access bits", "MFC JSON/EML/BIN dumps"],
        "parser_hints": ["mifare classic", "mfc", "static encrypted nonce", "gen1a", "magic", "default key"],
        "workflow": ["hf search", "hf mf info", "importar dump autorizado", "analisar setores/trailers/access bits", "comparar dumps"],
    },
    {
        "id": "hf_mfp",
        "family": "HF",
        "band": "13.56 MHz",
        "name": "MIFARE Plus",
        "standard": "NXP MIFARE Plus SL0/SL1/SL3",
        "frequency": "13.56 MHz",
        "risk": "MEDIUM",
        "description": "Inventário e análise de MIFARE Plus, incluindo nível de segurança, ACL e dumps autorizados.",
        "safe_commands": ["hf mfp info", "hf mfp acl", "hf mfp mad", "hf mfp ndefread", "hf mfp dump"],
        "blocked_examples": ["hf mfp chk", "hf mfp rdbl", "hf mfp rdsc", "hf mfp wrbl", "hf mfp chkey", "hf mfp chconf", "hf mfp commitp", "hf mfp initp", "hf mfp wrp", "hf mfp ndefformat", "hf mfp ndefwrite"],
        "artifacts": ["UID", "security level", "AES key references", "ACL", "MAD", "NDEF"],
        "parser_hints": ["mifare plus", "mfp", "security level", "sl0", "sl1", "sl3", "aes"],
        "workflow": ["hf search", "hf mfp info", "registrar security level", "analisar ACL/MAD sem alteração"],
    },
    {
        "id": "hf_mfu",
        "family": "HF",
        "band": "13.56 MHz",
        "name": "MIFARE Ultralight / NTAG",
        "standard": "NFC Forum Type 2 / MFU / NTAG",
        "frequency": "13.56 MHz",
        "risk": "MEDIUM",
        "description": "Tags Ultralight, NTAG21x, NTAG I2C e Ultralight AES para inventário e NDEF.",
        "safe_commands": ["hf mfu info", "hf mfu ndefread", "hf mfu dump"],
        "blocked_examples": ["hf mfu setkey", "hf mfu wipe", "hf mfu wrbl", "hf mfu restore", "hf mfu sim", "hf mfu setuid", "hf mfu cchk", "hf mfu aeschk", "hf mfu desbrute"],
        "artifacts": ["UID", "pages", "lock bytes", "counter", "signature", "NDEF"],
        "parser_hints": ["ultralight", "ntag", "mfu", "lock", "signature", "ndef"],
        "workflow": ["hf search", "hf mfu info", "hf mfu ndefread se autorizado", "registrar lock/counter/assinatura"],
    },
    {
        "id": "hf_mfdes",
        "family": "HF",
        "band": "13.56 MHz",
        "name": "MIFARE DESFire",
        "standard": "DESFire EV1/EV2/EV3 / ISO14443-4",
        "frequency": "13.56 MHz",
        "risk": "MEDIUM",
        "description": "Cartões DESFire para inventário de versão, UID, AIDs e estrutura lógica sem alteração.",
        "safe_commands": ["hf mfdes info", "hf mfdes getversion", "hf mfdes getuid", "hf mfdes freemem", "hf mfdes getaids", "hf mfdes lsapp"],
        "blocked_examples": ["hf mfdes auth", "hf mfdes chk", "hf mfdes detect", "hf mfdes bruteaid", "hf mfdes brutedamslot", "hf mfdes createapp", "hf mfdes deleteapp", "hf mfdes changekey", "hf mfdes write", "hf mfdes formatpicc"],
        "artifacts": ["UID", "hardware/software version", "AID list", "file list", "key settings"],
        "parser_hints": ["desfire", "ev1", "ev2", "ev3", "aid", "free memory", "getversion"],
        "workflow": ["hf search", "hf mfdes info", "hf mfdes getversion", "hf mfdes getaids se autorizado"],
    },
    {
        "id": "hf_ntag424",
        "family": "HF",
        "band": "13.56 MHz",
        "name": "NTAG 424 DNA",
        "standard": "NXP NTAG 424 DNA",
        "frequency": "13.56 MHz",
        "risk": "MEDIUM",
        "description": "Tag NFC avançada com recursos AES e SUN; integração com inventário e comandos laboratoriais conforme autorização.",
        "safe_commands": ["hf ntag424 info"],
        "blocked_examples": ["hf ntag424 auth", "hf ntag424 write", "hf ntag424 changefs", "hf ntag424 changekey"],
        "artifacts": ["UID", "file settings", "capability container", "NDEF hints"],
        "parser_hints": ["ntag 424", "ntag424", "dna", "sun", "aes"],
        "workflow": ["hf search", "hf ntag424 info", "registrar versão/configuração"],
    },
    {
        "id": "hf_felica",
        "family": "HF",
        "band": "13.56 MHz",
        "name": "FeliCa / ISO18092",
        "standard": "JIS X 6319-4 / ISO18092",
        "frequency": "13.56 MHz",
        "risk": "LOW",
        "description": "Cartões FeliCa e FeliCa Lite para identificação e metadados.",
        "safe_commands": ["hf felica info", "hf felica rqsyscode", "hf felica rqresponse"],
        "blocked_examples": ["hf felica raw", "hf felica sniff", "hf felica wrbl", "hf felica dump", "hf felica sim", "hf felica auth1", "hf felica auth2"],
        "artifacts": ["IDm", "PMm", "system code", "service code"],
        "parser_hints": ["felica", "idm", "pmm", "system code", "service code"],
        "workflow": ["hf search", "hf felica info", "registrar IDm/PMm/system code"],
    },
    {
        "id": "hf_topaz",
        "family": "HF",
        "band": "13.56 MHz",
        "name": "Topaz / NFC Type 1",
        "standard": "NFC Forum Type 1",
        "frequency": "13.56 MHz",
        "risk": "LOW",
        "description": "Topaz/Jewel/NFC Type 1 para inventário e leitura NDEF autorizada.",
        "safe_commands": ["hf topaz info"],
        "blocked_examples": ["hf topaz dump", "hf topaz raw", "hf topaz wrbl", "hf topaz sim", "hf topaz sniff"],
        "artifacts": ["UID", "HR", "memory size", "NDEF hints"],
        "parser_hints": ["topaz", "jewel", "type 1"],
        "workflow": ["hf search", "hf topaz info", "documentar UID/memória"],
    },
    {
        "id": "hf_st25ta",
        "family": "HF",
        "band": "13.56 MHz",
        "name": "ST25TA / NFC Type 4A",
        "standard": "ST25TA / NFC Type 4",
        "frequency": "13.56 MHz",
        "risk": "LOW",
        "description": "Tags ST25TA com foco em informação, NDEF e comandos laboratoriais conforme autorização.",
        "safe_commands": ["hf st25ta info", "hf st25ta ndefread"],
        "blocked_examples": ["hf st25ta protect", "hf st25ta pwd", "hf st25ta sim"],
        "artifacts": ["UID", "NDEF", "CC file", "protection flags"],
        "parser_hints": ["st25ta", "ndef", "type 4"],
        "workflow": ["hf search", "hf st25ta info", "hf st25ta ndefread se autorizado"],
    },
    {
        "id": "hf_seos",
        "family": "HF",
        "band": "13.56 MHz",
        "name": "HID Seos",
        "standard": "HID Seos / ISO14443-A",
        "frequency": "13.56 MHz",
        "risk": "MEDIUM",
        "description": "Inventário básico de cartões Seos. Operações PACS/ADF ficam documentadas, mas não são executadas por padrão.",
        "safe_commands": ["hf seos info"],
        "blocked_examples": ["hf seos sam", "hf seos pacs", "hf seos write", "hf seos adf", "hf seos gdf", "hf seos sim"],
        "artifacts": ["card info", "ISO14443-A hints"],
        "parser_hints": ["seos", "pacs", "adf"],
        "workflow": ["hf search", "hf seos info", "registrar apenas metadados permitidos"],
    },
    {
        "id": "lf_search",
        "family": "LF",
        "band": "125/134 kHz",
        "name": "LF Search / Auto Identify",
        "standard": "RRG/Iceman lf search",
        "frequency": "125/134 kHz",
        "risk": "LOW",
        "description": "Busca geral por tags LF conhecidas e tentativa de demodulação automática.",
        "safe_commands": ["lf search"],
        "blocked_examples": ["lf sniff", "lf sim", "lf relay", "lf cmdread"],
        "artifacts": ["protocol hint", "raw ID", "facility/card when decoded"],
        "parser_hints": ["em410x", "hid", "awid", "indala", "ioProx", "t55xx", "fdx-b"],
        "workflow": ["Aproximar tag LF", "Executar lf search", "Executar leitor específico se necessário", "registrar protocolo/ID"],
    },
    {
        "id": "lf_em410x",
        "family": "LF",
        "band": "125 kHz",
        "name": "EM410x / EM4102",
        "standard": "EM Marin ID",
        "frequency": "125 kHz",
        "risk": "HIGH",
        "description": "Credenciais LF simples baseadas em ID fixo. Alto risco quando usadas para controle de acesso.",
        "safe_commands": ["lf em 410x reader"],
        "blocked_examples": ["lf em 410x clone", "lf em 410x sim", "lf em 410x brute", "lf em 410x spoof", "lf em 410x watch"],
        "artifacts": ["EM ID", "raw bits", "facility/card quando inferível"],
        "parser_hints": ["em410x", "em 410x", "em4102", "em-marin"],
        "workflow": ["lf search", "lf em 410x reader", "registrar ID", "avaliar uso UID-only"],
    },
    {
        "id": "lf_hid",
        "family": "LF",
        "band": "125 kHz",
        "name": "HID Prox",
        "standard": "HID Prox / Wiegand",
        "frequency": "125 kHz",
        "risk": "HIGH",
        "description": "Credenciais HID Prox legadas; foco em inventário e decodificação Wiegand autorizada.",
        "safe_commands": ["lf hid reader", "wiegand decode"],
        "blocked_examples": ["lf hid clone", "lf hid sim", "lf hid brute", "lf hid watch"],
        "artifacts": ["raw HID", "facility code", "card number", "Wiegand format"],
        "parser_hints": ["hid prox", "wiegand", "facility", "card number", "fc"],
        "workflow": ["lf search", "lf hid reader", "registrar formato/facility/card", "recomendar migração para smartcard criptográfico"],
    },
    {
        "id": "lf_awid",
        "family": "LF",
        "band": "125 kHz",
        "name": "AWID",
        "standard": "AWID proximity",
        "frequency": "125 kHz",
        "risk": "HIGH",
        "description": "Credenciais AWID LF para inventário e leitura autorizada.",
        "safe_commands": ["lf awid reader"],
        "blocked_examples": ["lf awid clone", "lf awid sim", "lf awid brute", "lf awid watch"],
        "artifacts": ["raw AWID", "facility/card quando decodificado"],
        "parser_hints": ["awid", "fsk"],
        "workflow": ["lf search", "lf awid reader", "registrar ID e risco"],
    },
    {
        "id": "lf_indala",
        "family": "LF",
        "band": "125 kHz",
        "name": "Indala",
        "standard": "HID Indala",
        "frequency": "125 kHz",
        "risk": "HIGH",
        "description": "Credenciais Indala LF. Leitura de inventário e classificação do formato.",
        "safe_commands": ["lf indala reader"],
        "blocked_examples": ["lf indala clone", "lf indala sim", "lf indala brute"],
        "artifacts": ["raw Indala", "UID/formato"],
        "parser_hints": ["indala", "psk"],
        "workflow": ["lf search", "lf indala reader", "registrar formato"],
    },
    {
        "id": "lf_io",
        "family": "LF",
        "band": "125 kHz",
        "name": "ioProx",
        "standard": "Kantech ioProx",
        "frequency": "125 kHz",
        "risk": "HIGH",
        "description": "Credenciais ioProx LF para leitura autorizada e inventário.",
        "safe_commands": ["lf io reader"],
        "blocked_examples": ["lf io clone", "lf io sim", "lf io watch"],
        "artifacts": ["raw ioProx", "site/card quando decodificado"],
        "parser_hints": ["ioprox", "io prox", "kantech"],
        "workflow": ["lf search", "lf io reader", "registrar ID"],
    },
    {
        "id": "lf_fdx_b",
        "family": "LF",
        "band": "134.2 kHz",
        "name": "FDX-B Animal ID",
        "standard": "ISO11784/85",
        "frequency": "134.2 kHz",
        "risk": "LOW",
        "description": "Tags animais ISO11784/85 FDX-B para leitura e documentação.",
        "safe_commands": ["lf fdxb reader"],
        "blocked_examples": ["lf fdxb clone", "lf fdxb sim"],
        "artifacts": ["country code", "national ID", "animal bit", "raw"],
        "parser_hints": ["fdx-b", "fdxb", "iso11784", "animal"],
        "workflow": ["lf search", "lf fdxb reader", "registrar country/id"],
    },
    {
        "id": "lf_hitag",
        "family": "LF",
        "band": "125 kHz",
        "name": "Hitag 1/2/S/µ",
        "standard": "NXP Hitag",
        "frequency": "125 kHz",
        "risk": "MEDIUM",
        "description": "Inventário Hitag e comandos laboratoriais avançados conforme autorização.",
        "safe_commands": ["lf hitag info"],
        "blocked_examples": ["lf hitag dump", "lf hitag read", "lf hitag sniff", "lf hitag wrbl", "lf hitag sim", "lf hitag crack2", "lf hitag chk", "lf hitag cc"],
        "artifacts": ["tag info", "pages quando autorizado fora da UI"],
        "parser_hints": ["hitag", "hitag2", "hitag s", "hitag µ"],
        "workflow": ["lf search", "lf hitag info", "registrar tipo sem ataque"],
    },
    {
        "id": "lf_t55xx",
        "family": "LF",
        "band": "125 kHz",
        "name": "T55xx / T5577",
        "standard": "Atmel/Temic T55xx",
        "frequency": "125 kHz",
        "risk": "HIGH",
        "description": "Chip regravável frequentemente usado em laboratório RFID. Interface controlada pelo modo operacional configurado.",
        "safe_commands": ["lf t55xx detect", "lf t55xx info", "lf t55xx trace"],
        "blocked_examples": ["lf t55xx clonehelp", "lf t55xx dump", "lf t55xx read", "lf t55xx restore", "lf t55xx write", "lf t55xx bruteforce", "lf t55xx chk", "lf t55xx protect", "lf t55xx wipe"],
        "artifacts": ["modulation", "bitrate", "config block", "traceability"],
        "parser_hints": ["t55xx", "t5577", "temic", "modulation", "bitrate"],
        "workflow": ["lf search", "lf t55xx detect", "lf t55xx info", "marcar credencial regravável"],
    },
    {
        "id": "lf_em4x05",
        "family": "LF",
        "band": "125 kHz",
        "name": "EM4x05 / EM4305 / EM4469",
        "standard": "EM Microelectronic writable LF",
        "frequency": "125 kHz",
        "risk": "MEDIUM",
        "description": "Família EM4x05/EM4x69 para inventário e comandos laboratoriais conforme autorização.",
        "safe_commands": ["lf em 4x05 info"],
        "blocked_examples": ["lf em 4x05 brute", "lf em 4x05 chk", "lf em 4x05 dump", "lf em 4x05 read", "lf em 4x05 unlock", "lf em 4x05 wipe", "lf em 4x05 write"],
        "artifacts": ["config", "protection bits", "tag info"],
        "parser_hints": ["em4x05", "em4305", "em4469", "protection"],
        "workflow": ["lf search", "lf em 4x05 info", "registrar proteção/configuração"],
    },
    {
        "id": "wiegand",
        "family": "Data",
        "band": "Offline",
        "name": "Wiegand Decode",
        "standard": "Wiegand credential formats",
        "frequency": "Offline",
        "risk": "MEDIUM",
        "description": "Decodificação offline de formatos Wiegand para interpretar saídas HID/AWID/Indala autorizadas.",
        "safe_commands": ["wiegand list", "wiegand decode"],
        "blocked_examples": ["wiegand encode"],
        "artifacts": ["format", "facility code", "card number", "parity"],
        "parser_hints": ["wiegand", "facility", "card number", "format"],
        "workflow": ["Obter raw autorizado", "Executar decode fora de dados sensíveis", "registrar formato"],
    },
    {
        "id": "nfc_decode",
        "family": "NFC",
        "band": "Offline/13.56 MHz",
        "name": "NFC NDEF Decode",
        "standard": "NFC Forum NDEF",
        "frequency": "Offline/13.56 MHz",
        "risk": "LOW",
        "description": "Decodificação de NDEF e registros NFC de dumps ou leituras autorizadas.",
        "safe_commands": ["nfc decode"],
        "blocked_examples": ["nfc type4a write", "nfc mf cwrite", "nfc type4a format"],
        "artifacts": ["URI", "Text", "vCard", "MIME", "external records"],
        "parser_hints": ["ndef", "uri", "text record", "vcard", "mime"],
        "workflow": ["Importar dump/saída", "Executar decode offline", "registrar tipo de NDEF"],
    },
]

SAFE_COMMAND_DESCRIPTIONS = {
    normalize: f"{proto['name']} — {proto['description']}"
    for proto in PROTOCOLS
    for normalize in proto["safe_commands"]
}


def normalize_command(command: str) -> str:
    return " ".join(str(command or "").strip().lower().split())


def protocol_command_list(proto: dict) -> list[str]:
    seen = set()
    out: list[str] = []
    for command in (proto.get("safe_commands") or []) + (proto.get("blocked_examples") or []):
        normalized = normalize_command(command)
        if normalized and normalized not in seen:
            seen.add(normalized)
            out.append(command)
    return out


COMMAND_TO_PROTOCOL = {
    normalize_command(command): proto["id"]
    for proto in PROTOCOLS
    for command in protocol_command_list(proto)
}

SENSITIVE_KEYWORDS = sorted({
    "autopwn", "nested", "hardnested", "darkside", "staticnested", "brute", "bruteforce",
    "crack", "chk", "fchk", "restore", "write", "wrbl", "writedsfid", "writeafi",
    "setuid", "setkey", "changekey", "chkey", "format", "formatpicc", "wipe", "sim",
    "simulate", "clone", "spoof", "replay", "relay", "sniff", "raw", "tearoff",
    "apdufind", "magic", "unlock", "protect", "setconfig", "createapp", "deleteapp",
    "createfile", "deletefile", "eload", "esave", "eclr", "eset", "ecfill", "initp",
    "commitp", "wrp", "chconf",
})


def list_protocols(family: str | None = None, query: str | None = None) -> list[dict]:
    items = deepcopy(PROTOCOLS)
    if family:
        items = [p for p in items if p["family"].lower() == str(family).lower()]
    if query:
        q = str(query).lower().strip()
        items = [p for p in items if q in " ".join([
            p.get("id", ""), p.get("family", ""), p.get("name", ""), p.get("standard", ""),
            p.get("description", ""), " ".join(p.get("parser_hints", [])), " ".join(p.get("safe_commands", []))
        ]).lower()]
    for item in items:
        item["lab_commands"] = protocol_command_list(item)
        item["advanced_commands"] = item.get("blocked_examples", [])
    return items


def get_protocol(protocol_id: str) -> dict | None:
    for protocol in PROTOCOLS:
        if protocol["id"] == protocol_id:
            item = deepcopy(protocol)
            item["lab_commands"] = protocol_command_list(item)
            item["advanced_commands"] = item.get("blocked_examples", [])
            return item
    return None


def get_protocol_for_command(command: str) -> dict | None:
    protocol_id = COMMAND_TO_PROTOCOL.get(normalize_command(command))
    return get_protocol(protocol_id) if protocol_id else None


def is_known_safe_command(command: str) -> bool:
    return normalize_command(command) in {normalize_command(c) for c in SAFE_COMMAND_DESCRIPTIONS}


SMART_ACQUISITION_PATTERNS = [
    re.compile(r"^hf search$"),
    re.compile(r"^hf 14a info$"),
    re.compile(r"^hf 14a ndefread$"),
    re.compile(r"^hf 14b info$"),
    re.compile(r"^hf 14b ndefread$"),
    re.compile(r"^hf 15 info$"),
    re.compile(r"^hf mf info$"),
    re.compile(r"^hf mf ndefread$"),
    re.compile(r"^hf mf dump(?: --(?:mini|1k|2k|4k))?(?: -f [a-z0-9._-]+)?(?: -k [a-z0-9._-]+)?$"),
    re.compile(r"^hf mfu info$"),
    re.compile(r"^hf mfu ndefread$"),
    re.compile(r"^hf mfu dump(?: -f [a-z0-9._-]+)?(?: -z)?$"),
    re.compile(r"^hf mfp info$"),
    re.compile(r"^hf mfp acl$"),
    re.compile(r"^hf mfp mad$"),
    re.compile(r"^hf mfp ndefread$"),
    re.compile(r"^hf mfp dump$"),
    re.compile(r"^hf mfdes info$"),
    re.compile(r"^hf mfdes getversion$"),
    re.compile(r"^hf mfdes getuid$"),
    re.compile(r"^hf mfdes freemem$"),
    re.compile(r"^hf mfdes getaids$"),
    re.compile(r"^hf mfdes lsapp$"),
    re.compile(r"^hf ntag424 info$"),
    re.compile(r"^hf felica info$"),
    re.compile(r"^hf felica rqsyscode$"),
    re.compile(r"^hf felica rqresponse$"),
    re.compile(r"^hf topaz info$"),
]


def classify_smart_acquisition_command(command: str) -> dict:
    """Allow only internally generated read-only acquisition commands.

    File arguments are restricted to simple basenames so the workflow cannot be
    used to read or overwrite arbitrary local paths.
    """
    normalized = normalize_command(command)
    allowed = any(pattern.fullmatch(normalized) for pattern in SMART_ACQUISITION_PATTERNS)
    return {
        "allowed": allowed,
        "reason": "Comando read-only gerado pelo fluxo inteligente." if allowed else "Comando fora da allowlist do fluxo inteligente.",
        "normalized": normalized,
        "category": "smart_read_only" if allowed else "blocked",
        "protocol": COMMAND_TO_PROTOCOL.get(normalized),
        "sensitive": False,
        "sensitive_keywords": [],
        "requires_confirmation": False,
        "guard_mode": "SMART_ACQUISITION",
    }


def classify_command(command: str, mode: str = "ANALYSIS_ONLY") -> dict:
    normalized = normalize_command(command)
    mode = str(mode or "ANALYSIS_ONLY").upper()
    if mode not in {"ANALYSIS_ONLY", "OPERATOR_LAB"}:
        mode = "ANALYSIS_ONLY"
    if not normalized:
        return {"allowed": False, "reason": "Comando vazio.", "normalized": normalized, "category": "invalid", "guard_mode": mode}

    tokens = normalized.replace("-", " ").replace("_", " ").split()
    sensitive_hits = [kw for kw in SENSITIVE_KEYWORDS if kw in tokens]
    protocol_id = COMMAND_TO_PROTOCOL.get(normalized)
    basic = normalized in {normalize_command(c) for c in SAFE_COMMAND_DESCRIPTIONS}

    if mode == "ANALYSIS_ONLY":
        allowed = basic and not sensitive_hits
        reason = "Comando read-only do catálogo." if allowed else "Bloqueado pelo modo ANALYSIS_ONLY."
        category = "catalog_read_only" if allowed else "blocked"
        requires_confirmation = False
    else:
        allowed = True
        category = "catalog_basic" if basic else ("catalog_advanced" if protocol_id else "custom_operator")
        requires_confirmation = bool(sensitive_hits) or category in {"catalog_advanced", "custom_operator"}
        if requires_confirmation:
            reason = "Comando de operador liberado somente após confirmação explícita."
        else:
            reason = "Comando básico liberado em OPERATOR_LAB."

    return {
        "allowed": allowed,
        "reason": reason,
        "normalized": normalized,
        "category": category,
        "protocol": protocol_id,
        "sensitive": bool(sensitive_hits),
        "sensitive_keywords": sensitive_hits[:12],
        "requires_confirmation": requires_confirmation,
        "guard_mode": mode,
    }


def protocol_summary() -> dict:
    families: dict[str, int] = {}
    risks: dict[str, int] = {}
    safe_count = 0
    hf_count = 0
    lf_count = 0
    for p in PROTOCOLS:
        families[p["family"]] = families.get(p["family"], 0) + 1
        risks[p["risk"]] = risks.get(p["risk"], 0) + 1
        safe_count += len(p.get("safe_commands", []))
        hf_count += int(p["family"].upper() == "HF")
        lf_count += int(p["family"].upper() == "LF")
    return {
        "protocols": len(PROTOCOLS),
        "families": families,
        "risk_levels": risks,
        "hf_protocols": hf_count,
        "lf_protocols": lf_count,
        "safe_commands": safe_count,
        "advanced_commands": sum(len(p.get("blocked_examples", [])) for p in PROTOCOLS),
        "catalog_commands": sum(len(protocol_command_list(p)) for p in PROTOCOLS),
        "sensitive_keywords": len(SENSITIVE_KEYWORDS),
        "guard_mode": "runtime-configured",
        "upstream": "RfidResearchGroup/proxmark3",
    }


def suggest_protocol_from_text(text: str) -> list[dict]:
    raw = str(text or "").lower()
    scored = []
    for proto in PROTOCOLS:
        score = 0
        for hint in proto.get("parser_hints", []):
            if hint.lower() in raw:
                score += 3
        for word in [proto.get("name", ""), proto.get("standard", ""), proto.get("id", "")]:
            for token in str(word).lower().replace("/", " ").replace("-", " ").split():
                if len(token) > 2 and token in raw:
                    score += 1
        if score:
            item = deepcopy(proto)
            item["score"] = score
            scored.append(item)
    return sorted(scored, key=lambda x: x["score"], reverse=True)[:8]
