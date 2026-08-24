# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 3.2.x | Yes |

## Reporting a Vulnerability

Report security issues privately to repository maintainers. Do not open public issues for vulnerabilities.

When reporting:

- do **not** include real keys, passwords, tokens, card UIDs or dump contents in reports;
- include reproduction steps and affected version (`VERSION` / `git describe`);
- allow time for a fix before any public disclosure.

## Authorized Laboratory Use

This project is intended for laboratory use and environments where the operator is explicitly authorized to analyze the RFID/NFC material in question. Do not use it against systems or credentials you do not own or are not authorized to assess.

## Deployment Guidance

- Keep the application bound to `127.0.0.1` unless a properly configured TLS reverse proxy is used.
- For proxied production set `UTAMO_ENVIRONMENT=production`, a strong `UTAMO_SECRET_KEY` (≥ 32 chars), `UTAMO_SECURE_COOKIE=1`, `UTAMO_TRUSTED_HOSTS`, and the exact trusted proxy hop count.
- Run a single application process; SQLite and in-memory locks are not designed for multi-worker deployment.
- Restrict Proxmark3 client locations with `UTAMO_PM3_ALLOWED_ROOTS`; keep `ANALYSIS_ONLY` for ordinary analysis.

## Secrets and Sensitive Data

- Never commit `.env` files, private keys, tokens or real credential dumps.
- Protect `runtime/first_run_credentials.txt`, the SQLite database, dumps and reports; all live under `runtime/`.
- Handle RFID/RF dumps responsibly: they may contain real card identifiers (UIDs) and key material. Sanitize before sharing.
- The smart workflow is read-only by design and must not be extended with key recovery, write, simulation, replay, sniffing or arbitrary APDU operations.
