# P0–P3 hardening report

## P0 — Security

Implemented:

- authentication for every application and API route;
- session CSRF and Bearer-token API access;
- initial random credentials stored with restricted permissions;
- local bind `127.0.0.1` and debug disabled by default;
- no wildcard CORS;
- CSP, frame denial, MIME sniffing protection and no-store responses;
- upload and form-memory limits;
- Proxmark executable/port loaded only from stored administrator configuration;
- path/port/timeout validation;
- subprocess argument list with `shell=False`;
- explicit modes `ANALYSIS_ONLY` and `OPERATOR_LAB`;
- explicit per-execution confirmation for advanced, sensitive and uncatalogued operator commands;
- audit records for blocked, rejected, successful and failed PM3 commands;
- key masking in generated/exported reports, including trailer `block_hex` and sector profiles.

## P1 — Analysis reliability

Implemented:

- one normalized analysis engine used by current and legacy endpoints;
- content-aware JSON/text/binary/MFU parsing;
- MFU current 56-byte prefix, old 48-byte prefix and raw pages;
- exact common Classic sizes and partial-dump classification;
- Type 2 UID/BCC validation;
- complete Value Block redundancy and address-complement validation;
- MAD1/MAD2 candidate checks using GPB, public MAD Key A and CRC-8;
- Access Bits decoding through one implementation;
- separate counts for sectors with public keys, Key A, Key B and both;
- explicit static-security evidence and caveat against deriving cloning feasibility from a dump.

## P2 — Upstream compatibility and testing

Implemented:

- MIFARE Plus profile and metadata model, including security level;
- DESFire logical JSON representation for applications/files;
- upstream reference stored with each dump analysis;
- Proxmark client, firmware and bootrom lines captured from output;
- offline catalog validator against a locally pinned `doc/commands.md`;
- schema version table and reference SQL migrations;
- unit and web-security tests;
- CI for supported Python versions.

Hardware-dependent validation still required after deployment:

- actual PM3 serial communication on the target Windows installation;
- command/output compatibility with the exact installed Iceman commit;
- representative real dumps for every desired card generation;
- PDF layout with very large card dumps.

## P3 — Cleanup

Implemented:

- removed inactive blueprints and old SDR/spectrum/jammer/LoRa/NRF24/CC1101 code;
- removed bundled `.git`, `.venv`, caches, databases, dumps, reports and captures;
- one runtime database and runtime data directory;
- current README, environment example, changelog and startup scripts;
- legacy database migration utility;
- distribution audit utility.

## Security boundary

`OPERATOR_LAB` is deliberately a powerful local operator mode. It does not make an arbitrary command safe; it requires explicit activation and per-command confirmation for advanced, sensitive or uncatalogued operations while retaining authentication, audit, timeout, path, port and shell protections. Keep the service bound locally unless a separately secured reverse proxy is deployed.
