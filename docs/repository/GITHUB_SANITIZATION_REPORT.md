# GitHub Sanitization Report

Export of UTAMO RF Lab v3.2.0 into a clean, GitHub-ready repository. The original project was treated as read-only; no Git history, database, dump or local state was transported.

## Source / Destination

- **SOURCE**: private laboratory working tree (v3.2.0 audited baseline)
- **DESTINATION**: this repository (fresh `git init`, branch `main`, new history)

## Classification Summary

| Category | Decision |
|---|---|
| SOURCE CODE | Copied (`app/`, `main.py`, `tools/`) |
| TEST | Copied (`tests/` — hermetic, artificial fixtures only) |
| DOCUMENTATION | Copied/sanitized (`docs/`, README, CHANGELOG, SECURITY, CONTRIBUTING) |
| CONFIG TEMPLATE | Copied (`.env.example`, `.github/workflows/tests.yml`, start scripts) |
| STATIC ASSET | Copied (`app/static/`, `app/templates/`) |
| SCHEMA/MIGRATIONS | Copied (`migrations/*.sql` — reference SQL only) |
| DATABASE | Excluded — 0 tracked |
| SESSION/RUNTIME DATA | Excluded (`runtime/` not copied) — 0 tracked |
| DUMP / CAPTURE / REPORT DATA | Excluded (real lab dumps, reports and captures) — 0 tracked |
| SECRET | Excluded (`flask_secret.key`, `first_run_credentials.txt`, `.env*` values) — 0 tracked |
| LOG | Excluded — 0 tracked |
| BACKUP | Excluded — 0 tracked |
| CACHE/TEMP | Excluded (`__pycache__`, `.pytest_cache`, `.ruff_cache`) — 0 tracked |
| INTERNAL AUDIT EVIDENCE | Excluded (internal audit/hardening/UI-redesign working documents kept out of the public tree; product-appropriate versions retained in `docs/`) |
| DEV/AI ARTIFACTS | Excluded |

## Files

- FILES CONSIDERED (source working tree): full recursive inventory
- FILES EXPORTED: 87 tracked files (~0.4 MB)
- LARGEST TRACKED FILE: `app/rf/card_dump_analyzer.py`
- FILES >5 MB: none

## Exclusions Applied

- Databases excluded: all `*.db` / SQLite artifacts
- Real dumps excluded: `*.json` dump exports, `*.eml`, `*.rfraw` captures from laboratory use
- Generated reports excluded: real analysis/report JSON artifacts
- Sessions excluded: smart-scan workspaces, workflow evidence, favorites history
- Logs excluded: log directory contents
- Backups excluded: none present in source root beyond ignored patterns
- Secrets excluded: runtime secret key, first-run credentials file

## Personal Data / Private Paths

- No personal names, usernames, hostnames, e-mails or device identifiers in the tree.
- No absolute personal paths in code or documentation. Remaining Windows-style strings are synthetic test fixtures (`C:\private\...`, `C:\ProxSpace\pm3` example) or generic URI prefix tables.
- Hardware configuration uses placeholders/settings stored at runtime, never committed.

## Secret Scan

- Pattern scan over all exported text files (keys, tokens, passwords, private key blocks, high-entropy hex): **0 findings**.
- Real card UIDs / MIFARE keys from laboratory dumps: **0 occurrences** (only the public factory default `FFFFFFFFFFFF` used by masking tests).
- Pre-stage scan on staged content: **PASS (SECRETS FOUND: 0)**.
- Clean clone scan: **PASS**.

## Verification Performed on This Copy

- Fresh database initialization in isolated temp runtime: PASS
- Hardwareless startup (no Proxmark3 connected): login + main pages HTTP 200: PASS
- Artificial dump import → normalized analysis → report listing: PASS
- Invalid import rejected with HTTP 400 (no 500): PASS
- Full pytest suite executed on this copy: PASS (58 tests)
- Ruff check: PASS

## Clean History Guarantee

This repository was initialized with a brand-new Git history. The original `.git` directory was never copied. Old commits, deleted dumps and historical secrets cannot be recovered from this repository.
