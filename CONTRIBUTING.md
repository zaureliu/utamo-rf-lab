# Contributing to UTAMO RF Lab

Thanks for considering a contribution. Please follow these rules to keep the project safe and maintainable.

## Setup

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate   |   Linux/macOS: . .venv/bin/activate
python -m pip install -r requirements-dev.txt
```

Copy `.env.example` values into your environment if you need non-default settings. Never create a committed `.env`.

## Before Opening a Pull Request

Run the full local check:

```bash
python tools/security_audit.py
python -m ruff check app tests tools main.py
python -m pytest -q
```

All three must pass. Tests must be hermetic: temporary runtime directory, no hardware required, no real COM ports, no network.

## Coding Rules

- Python 3.11+ compatible code; type hints encouraged; Ruff must stay clean (`app tests tools main.py`).
- No new dependencies without justification; keep constraints bounded (`>=x,<y`) in both `pyproject.toml` and `requirements.txt`.
- Keep the single-process/single-instance architecture; do not introduce distributed queues or server databases without prior discussion.
- Preserve existing API contracts and route behavior; breaking changes require explicit discussion first.

## Hard Security Rules

- **No secrets**: never commit credentials, tokens, API keys, private keys or `.env` files.
- **No real card dumps**: never commit real captures, UIDs of personal cards, MIFARE keys or operator data. Use artificial, clearly-labeled fixtures only.
- **No arbitrary shell execution**: subprocess usage remains argument-list based with `shell=False`. Command execution stays behind the catalog allowlist and validation.
- Hardware-related changes (serial layer, command catalog, smart workflow plans) require tests covering policy/validation paths, including negative cases.

## UI Changes

Any interface change requires smoke testing: login, main pages, one import flow and one analysis render. Keep CSP strict — no inline scripts/styles/handlers.

## Commit Style

Use short, imperative subjects, e.g. `fix: reject invalid port before spawn` or `feat: add MFU page-format regression test`.
