from __future__ import annotations

import os
import secrets
from datetime import timedelta
from pathlib import Path
from typing import ClassVar

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_DIR = Path(os.environ.get("UTAMO_RUNTIME_DIR") or PROJECT_ROOT / "runtime").resolve()

def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw_value = os.environ.get(name)
    if raw_value is None:
        return default
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise RuntimeError(f"{name} deve ser um numero inteiro.") from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} deve estar entre {minimum} e {maximum}.")
    return value


def _list_env(name: str) -> list[str] | None:
    values = [item.strip() for item in os.environ.get(name, "").split(",") if item.strip()]
    return values or None


def load_or_create_secret() -> str:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    configured = os.environ.get("UTAMO_SECRET_KEY", "").strip()
    if configured:
        return configured
    path = RUNTIME_DIR / "flask_secret.key"
    if path.exists():
        value = path.read_text(encoding="utf-8").strip()
        if value:
            return value
    value = secrets.token_urlsafe(48)
    path.write_text(value, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return value


class Config:
    UTAMO_ENVIRONMENT = os.environ.get("UTAMO_ENVIRONMENT", "local").strip().lower()
    SECRET_KEY = os.environ.get("UTAMO_SECRET_KEY", "").strip() or None
    SESSION_PERMANENT = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    SESSION_COOKIE_SECURE = env_bool("UTAMO_SECURE_COOKIE", False)
    SESSION_COOKIE_NAME = "utamo_rflab_session"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=env_int("UTAMO_SESSION_HOURS", 8, 1, 72))
    TRUSTED_HOSTS = _list_env("UTAMO_TRUSTED_HOSTS")
    TRUSTED_PROXY_HOPS = env_int("UTAMO_TRUSTED_PROXY_HOPS", 0, 0, 10)
    LOGIN_MAX_FAILURES = env_int("UTAMO_LOGIN_MAX_FAILURES", 5, 1, 100)
    LOGIN_WINDOW_SECONDS = env_int("UTAMO_LOGIN_WINDOW_SECONDS", 900, 60, 86400)
    LOGIN_MAX_CLIENTS = env_int("UTAMO_LOGIN_MAX_CLIENTS", 10_000, 100, 100_000)

    # 8 MiB by default. Flask rejects larger requests before route code reads them.
    MAX_CONTENT_LENGTH = env_int("UTAMO_MAX_UPLOAD_BYTES", 8 * 1024 * 1024, 64 * 1024, 64 * 1024 * 1024)
    MAX_FORM_MEMORY_SIZE = env_int("UTAMO_MAX_FORM_MEMORY_BYTES", 2 * 1024 * 1024, 64 * 1024, 16 * 1024 * 1024)

    PM3_MODE = os.environ.get("UTAMO_PM3_MODE", "ANALYSIS_ONLY").strip().upper()
    if PM3_MODE not in {"ANALYSIS_ONLY", "OPERATOR_LAB"}:
        PM3_MODE = "ANALYSIS_ONLY"
    PM3_MAX_TIMEOUT = env_int("UTAMO_PM3_MAX_TIMEOUT", 180, 5, 600)
    PM3_ALLOWED_ROOTS: ClassVar[list[Path]] = [
        Path(part.strip()).expanduser().resolve()
        for part in os.environ.get("UTAMO_PM3_ALLOWED_ROOTS", "").split(os.pathsep)
        if part.strip()
    ]

    SMART_SCAN_DIR = Path(os.environ.get("UTAMO_SMART_SCAN_DIR") or RUNTIME_DIR / "smart_scans").resolve()
    SMART_SCAN_MAX_COMMANDS = env_int("UTAMO_SMART_SCAN_MAX_COMMANDS", 12, 3, 24)
    SMART_SCAN_TOTAL_TIMEOUT = env_int("UTAMO_SMART_SCAN_TOTAL_TIMEOUT", 480, 60, 1800)
    SMART_AUTO_DUMP = env_bool("UTAMO_SMART_AUTO_DUMP", True)
    SMART_READ_NDEF = env_bool("UTAMO_SMART_READ_NDEF", True)

    EXPORT_FULL_KEYS = env_bool("UTAMO_EXPORT_FULL_KEYS", False)
    UPSTREAM_PM3_COMMIT = os.environ.get("UTAMO_PM3_UPSTREAM_COMMIT", "master").strip() or "master"


def validate_runtime_config(app) -> None:
    environment = str(app.config.get("UTAMO_ENVIRONMENT", "local")).strip().lower()
    if environment not in {"local", "testing", "production"}:
        raise RuntimeError("UTAMO_ENVIRONMENT deve ser local, testing ou production.")
    app.config["UTAMO_ENVIRONMENT"] = environment

    secret_key = str(app.config.get("SECRET_KEY") or "")
    if environment == "production":
        if len(secret_key) < 32:
            raise RuntimeError("UTAMO_SECRET_KEY deve ter ao menos 32 caracteres em producao.")
        if not app.config.get("SESSION_COOKIE_SECURE"):
            raise RuntimeError("UTAMO_SECURE_COOKIE deve estar habilitado em producao.")
        if not app.config.get("TRUSTED_HOSTS"):
            raise RuntimeError("UTAMO_TRUSTED_HOSTS deve ser configurada em producao.")
        if app.config.get("PM3_MODE") == "OPERATOR_LAB" and not app.config.get("PM3_ALLOWED_ROOTS"):
            raise RuntimeError(
                "UTAMO_PM3_ALLOWED_ROOTS e obrigatoria para OPERATOR_LAB em producao."
            )
