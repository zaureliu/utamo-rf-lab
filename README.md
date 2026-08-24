# UTAMO RF Lab

Local, authenticated laboratory application for **authorized RFID/NFC dump analysis**, focused on MIFARE family cards and controlled integration with the Proxmark3 (Iceman/RRG) client.

Version: **3.2.0**

## Overview

UTAMO RF Lab turns raw card dumps and Proxmark3 output into structured, evidence-based analysis while keeping dangerous operations out of the interface. It runs as a single local web application backed by SQLite, with authentication required for every route.

## Core Capabilities

- Authenticated web UI (session login, CSRF protection) and Bearer-token API.
- Normalized dump analyzer: Proxmark3 JSON, `.eml`, `.txt`, `.hex`, `.mct`, `.bin`, `.dump`, `.mfd`, MFU 56/48-byte and page formats, Type 2/NTAG, Classic/Plus blocks and logical DESFire JSON. Extension is only a hint; content and structure are validated.
- MIFARE Classic/Plus sector and trailer analysis: Key A/B presence, Access Bits decoding, Value Blocks, MAD checks, default-key statistics, empty-sector detection, structural clone comparison.
- Masked reporting by default: keys, trailer bytes and sector-profile key fields are hidden unless explicitly enabled.
- Read-only smart acquisition workflow ("Detect and analyze") with progress, cancellation and per-port locking.
- Session history, favorites and operator-paste provenance tracking (`source="operator_paste"`).
- PDF/JSON/CSV report export with CSV formula-injection neutralization.

## Architecture

```text
Browser / API
  -> authentication + CSRF/Bearer + rate limit
  -> import -> normalized parser -> evidence/risk -> report + SQLite
  -> PM3 command -> policy -> validation -> subprocess (shell=False) -> parser + audit
  -> smart read -> classification -> read-only plan -> workspace -> normalized analyzer
```

- `app/security.py` — authentication, authorization, CSRF, login throttling.
- `app/rf/` — domain logic, analysis, protocols, reports, sessions, smart workflow.
- `app/rf_engine/proxmark3.py` — the single execution boundary for the external client.
- `app/database/db.py` — versioned SQLite schema (version 6), settings and audit trail.
- `runtime/` — local data boundary; never part of the source tree.

Single instance, single process by design (SQLite + in-memory port locks). For remote access use one worker behind a TLS reverse proxy.

## Supported Workflows

- Manual dump upload or paste (`operator_paste` provenance preserved).
- Direct Proxmark3 command execution through the catalog allowlist.
- Smart scan: `hf search` based identification, conservative family classification, family-specific read-only command plan, UID-consistency verification and automatic hand-off of generated dumps to the normalized analyzer.
- Dump comparison and structural similarity (clone-evidence) analysis.
- Maintenance operations (clear logs/events) from the UI.

## Proxmark3 Integration

- Client execution uses `shell=False`, validated client path/port, timeouts and a local command catalog derived from the public Iceman documentation.
- Default mode is `ANALYSIS_ONLY`: only catalogued read-only commands are accepted. Write, simulation, cracking, replay and sniffing operations are blocked.
- `OPERATOR_LAB` enables advanced operations behind explicit per-execution confirmation; it must be enabled manually and restricted with `UTAMO_PM3_ALLOWED_ROOTS`.
- The parser does not depend on a connected device: pasted output and imported files feed the same analysis pipeline.

## Offline Analysis

The full analysis engine works without any hardware: import dumps produced elsewhere (or synthetic ones), paste client output, compare dumps and generate reports entirely offline.

## MIFARE Analysis

Static forensic analysis of MIFARE Classic/Plus/Ultralight/NTAG/DESFire dumps: identity extraction with BCC validation, trailer and Access Bits decoding, MAD1/MAD2 consistency, Value Block redundancy, default-key statistics and explicit separation of static evidence from cloning conclusions. Static analysis never proves clonability.

## Sessions

Analysis sessions preserve history of executed commands, imported dumps, favorites and smart scans in the local database. All session data stays under `runtime/` and out of version control.

## Requirements

- Python 3.11+ (CI covers 3.11–3.14)
- Flask, pyserial, reportlab (installed from `requirements.txt`)
- Optional hardware: Proxmark3 client for live acquisition — not required for installation, tests or offline analysis

## Installation

Windows:

```bat
start_windows.bat
```

Linux/macOS:

```bash
chmod +x start_linux.sh
./start_linux.sh
```

Manual:

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate   |   Linux/macOS: . .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

On first start, administrator credentials and the initial API token are written to `runtime/first_run_credentials.txt`. Protect this file and remove it after storing the values securely.

## Configuration

Copy relevant variables from [.env.example](.env.example) into your environment mechanism. Highlights:

| Variable | Purpose |
|---|---|
| `UTAMO_HOST` / `UTAMO_PORT` | Bind address (loopback by default) |
| `UTAMO_SECRET_KEY` | Flask secret (auto-generated per runtime if unset) |
| `UTAMO_ADMIN_PASSWORD` / `UTAMO_RESET_ADMIN_PASSWORD` | Credential bootstrap/rotation |
| `UTAMO_ENVIRONMENT` | `local`, `testing` or `production` |
| `UTAMO_RUNTIME_DIR` | Local state directory |
| `UTAMO_PM3_MODE` | `ANALYSIS_ONLY` (default) or `OPERATOR_LAB` |
| `UTAMO_PM3_ALLOWED_ROOTS` | Allowed Proxmark client locations |

Production requires `UTAMO_ENVIRONMENT=production`, a ≥32-character `UTAMO_SECRET_KEY`, `UTAMO_SECURE_COOKIE=1`, HTTPS behind a reverse proxy and `UTAMO_TRUSTED_HOSTS`.

## Running

```bash
python main.py
```

Open `http://127.0.0.1:5000`. Remote bind is blocked unless `UTAMO_ALLOW_REMOTE=1` is set explicitly.

## Hardware Detection

Serial COM ports are discovered via pyserial (`app/hardware/com_port_scanner.py`) at request time — no hardcoded ports. The Proxmark3 client path and port are stored as administrator settings in the local database. Integration available; hardware validation environment-dependent.

## Security Boundaries

- Intended for **laboratory and authorized environments** only.
- No remote shell; no arbitrary command execution. Proxmark invocation goes through an allowlist with path/port/command/timeout validation and `shell=False`.
- No jamming and no destructive automation are implemented.
- Key recovery, brute force, write, clone/simulate/replay/sniffing and arbitrary APDU automation are deliberately excluded from both manual and smart workflows.
- Upload size limits, strict CSP without inline script/style, security headers and audited PM3 command history.

## Testing

```bash
python -m pip install -r requirements-dev.txt
python tools/security_audit.py
python -m ruff check app tests tools main.py
python -m pytest -q
```

Tests are hermetic (temporary runtime directory, no hardware, no real ports). Hardware-dependent paths are covered by fixtures/mocks so CI never requires a connected Proxmark3.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/SMART_CARD_WORKFLOW.md](docs/SMART_CARD_WORKFLOW.md)
- [docs/HARDENING_P0_P3.md](docs/HARDENING_P0_P3.md)
- [docs/RFID_CARD_DUMP_ANALYZER_REPORT.md](docs/RFID_CARD_DUMP_ANALYZER_REPORT.md)
- [docs/RRG_PROTOCOL_IMPLEMENTATION.md](docs/RRG_PROTOCOL_IMPLEMENTATION.md)
- [docs/UPSTREAM_COMPATIBILITY.md](docs/UPSTREAM_COMPATIBILITY.md)
- [docs/architecture/DATABASE_MIGRATION_READINESS.md](docs/architecture/DATABASE_MIGRATION_READINESS.md)
- [SECURITY.md](SECURITY.md) · [CONTRIBUTING.md](CONTRIBUTING.md) · [CHANGELOG.md](CHANGELOG.md)

## Project Status

Production readiness audit: **PASS** (full test suite green, zero HTTP 500s, zero tracebacks on the audited baseline).

Hardware support matrix (real state):

| Component | Status |
|---|---|
| Proxmark3 | Supported / integration present |
| Chameleon Ultra | Not implemented |
| CC1101 | Not implemented |
| nRF24 | Not implemented |
| LoRa SX1262 | Not implemented |
| PN532 | Not implemented |

## License

No license has been selected yet — owner decision required. Until a license is added, all rights reserved by the project owner.
