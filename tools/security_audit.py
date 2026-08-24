#!/usr/bin/env python3
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = {
    r"shell\s*=\s*True": "shell=True",
    r"cors_allowed_origins\s*=\s*[\"']\*[\"']": "wildcard Socket.IO CORS",
    r"CORS\([^\n]*origins\s*=\s*[\"']\*[\"']": "wildcard CORS",
    r"host\s*=\s*[\"']0\.0\.0\.0[\"']": "public bind hardcoded",
    r"debug\s*=\s*True": "debug enabled",
    r"request\.form\.get\([\"\']client_path[\"\']|data\.get\([\"\']client_path[\"\']": "request-controlled PM3 executable",
    r"LAB_UNRESTRICTED": "obsolete unrestricted mode",
}
FORBIDDEN_DIR_NAMES = {".venv", "venv", ".git", ".pytest_cache", ".ruff_cache", "__pycache__"}
SENSITIVE_SUFFIXES = {
    ".bin",
    ".db",
    ".dump",
    ".eml",
    ".key",
    ".mfd",
    ".mfu",
    ".pyc",
    ".rfraw",
    ".sqlite",
}
SENSITIVE_NAMES = {"first_run_credentials.txt", "flask_secret.key"}
SENSITIVE_ROOTS = {"data", "logs", "runtime"}
SECRET_SIGNATURES = {
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----": "private key",
    r"AKIA[0-9A-Z]{16}": "AWS access key",
    r"gh[pousr]_[A-Za-z0-9_]{20,}": "GitHub token",
    r"sk-[A-Za-z0-9]{20,}": "API token",
}


def repository_files() -> list[Path]:
    git = shutil.which("git")
    if git:
        result = subprocess.run(  # noqa: S603
            [
                git,
                "-c",
                f"safe.directory={ROOT.as_posix()}",
                "-C",
                str(ROOT),
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
            ],
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            return [
                ROOT / item.decode("utf-8", errors="surrogateescape")
                for item in result.stdout.split(b"\0")
                if item
            ]

    return [
        path
        for path in ROOT.rglob("*")
        if path.is_file() and not any(part in FORBIDDEN_DIR_NAMES for part in path.relative_to(ROOT).parts)
    ]


def main() -> int:
    findings = []
    files = repository_files()
    source_files = [
        path
        for path in files
        if path.suffix == ".py"
        and (path.name == "main.py" or path.relative_to(ROOT).parts[0] == "app")
        and path.exists()
    ]
    for path in source_files:
        text = path.read_text(encoding="utf-8", errors="replace")
        for pattern, label in FORBIDDEN.items():
            if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                findings.append(f"{path.relative_to(ROOT)}: {label}")
    for path in files:
        if not path.exists() or not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if any(part in FORBIDDEN_DIR_NAMES for part in relative.parts):
            findings.append(f"tracked cache/environment path: {relative}")
        if path.name in SENSITIVE_NAMES:
            findings.append(f"tracked secret file: {relative}")
        if path.suffix.lower() in SENSITIVE_SUFFIXES and "tests/fixtures" not in path.as_posix():
            findings.append(f"tracked runtime/sensitive file: {relative}")
        if relative.parts and relative.parts[0] in SENSITIVE_ROOTS and path.name != ".gitkeep":
            findings.append(f"tracked runtime artifact: {relative}")
        if path.name == ".env" or (path.name.startswith(".env.") and path.name != ".env.example"):
            findings.append(f"tracked environment file: {relative}")
        if path.suffix.lower() in {".py", ".js", ".html", ".md", ".txt", ".toml", ".yml", ".yaml"}:
            text = path.read_text(encoding="utf-8", errors="replace")
            for pattern, label in SECRET_SIGNATURES.items():
                if re.search(pattern, text):
                    findings.append(f"{relative}: possible {label}")
    if findings:
        print("SECURITY AUDIT FAILED")
        for item in findings:
            print("-", item)
        return 1
    print("SECURITY AUDIT OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
