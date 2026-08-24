from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from collections import OrderedDict, deque
from functools import wraps
from pathlib import Path
from threading import Lock
from urllib.parse import urlparse

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from app.config import RUNTIME_DIR
from app.database.db import add_audit, get_setting, set_setting

security_bp = Blueprint("security_bp", __name__)
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


class LoginRateLimiter:
    def __init__(self, max_clients: int = 10_000) -> None:
        self._attempts: OrderedDict[str, deque[float]] = OrderedDict()
        self._max_clients = max(100, int(max_clients))
        self._lock = Lock()

    def _events(self, key: str) -> deque[float]:
        events = self._attempts.get(key)
        if events is None:
            if len(self._attempts) >= self._max_clients:
                self._attempts.popitem(last=False)
            events = deque()
            self._attempts[key] = events
        else:
            self._attempts.move_to_end(key)
        return events

    def is_limited(self, key: str, limit: int, window_seconds: int) -> bool:
        cutoff = time.monotonic() - window_seconds
        with self._lock:
            events = self._events(key)
            while events and events[0] < cutoff:
                events.popleft()
            return len(events) >= limit

    def record_failure(self, key: str, window_seconds: int) -> None:
        cutoff = time.monotonic() - window_seconds
        with self._lock:
            events = self._events(key)
            while events and events[0] < cutoff:
                events.popleft()
            events.append(time.monotonic())

    def clear(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)

    @property
    def client_count(self) -> int:
        with self._lock:
            return len(self._attempts)



def _login_key() -> str:
    return request.remote_addr or "local"

def _credential_file() -> Path:
    return RUNTIME_DIR / "first_run_credentials.txt"


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def ensure_bootstrap_credentials() -> None:
    username = get_setting("admin_username", "").strip()
    password_hash = get_setting("admin_password_hash", "").strip()
    api_token_hash = get_setting("api_token_hash", "").strip()

    env_username = os.environ.get("UTAMO_ADMIN_USERNAME", "admin").strip() or "admin"
    env_password = os.environ.get("UTAMO_ADMIN_PASSWORD", "")
    reset_password = os.environ.get("UTAMO_RESET_ADMIN_PASSWORD", "").strip().lower() in {"1", "true", "yes", "on"}

    generated_password = None
    generated_token = None

    if not username:
        username = env_username
        set_setting("admin_username", username)

    if not password_hash or (reset_password and env_password):
        password = env_password or secrets.token_urlsafe(18)
        generated_password = password
        set_setting("admin_password_hash", generate_password_hash(password, method="scrypt"))

    if not api_token_hash:
        generated_token = secrets.token_urlsafe(32)
        set_setting("api_token_hash", _hash_token(generated_token))

    if generated_password or generated_token:
        lines = [
            "Utamo RFID / Proxmark3 Lab - credenciais iniciais",
            "Troque a senha definindo UTAMO_ADMIN_PASSWORD e UTAMO_RESET_ADMIN_PASSWORD=1 antes de iniciar.",
            f"Usuário: {username}",
        ]
        if generated_password:
            lines.append(f"Senha: {generated_password}")
        else:
            lines.append("Senha: mantida da configuração existente")
        if generated_token:
            lines.append(f"API token: {generated_token}")
        else:
            lines.append("API token: mantido da configuração existente")
        path = _credential_file()
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            pass
        print(f"[SECURITY] Credenciais iniciais gravadas em: {path}")


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def _is_api_token_valid() -> bool:
    header = request.headers.get("Authorization", "")
    if not header.lower().startswith("bearer "):
        return False
    supplied = header.split(None, 1)[1].strip()
    expected_hash = get_setting("api_token_hash", "")
    return bool(supplied and expected_hash and hmac.compare_digest(_hash_token(supplied), expected_hash))


def is_authenticated() -> bool:
    return bool(session.get("authenticated")) or _is_api_token_valid()


def _safe_next_url(value: str | None) -> str:
    if not value:
        return url_for("dashboard_bp.index")
    parsed = urlparse(value)
    if parsed.scheme or parsed.netloc or not value.startswith("/"):
        return url_for("dashboard_bp.index")
    return value


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not is_authenticated():
            if request.path.startswith("/api/"):
                return jsonify({"status": "error", "message": "authentication required"}), 401
            return redirect(url_for("security_bp.login", next=request.full_path))
        return view(*args, **kwargs)

    return wrapped


@security_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        key = _login_key()
        limiter = current_app.extensions["login_limiter"]
        window_seconds = current_app.config["LOGIN_WINDOW_SECONDS"]
        if limiter.is_limited(
            key,
            current_app.config["LOGIN_MAX_FAILURES"],
            window_seconds,
        ):
            add_audit(request.remote_addr or "local", "auth.login", "admin", "rate_limited", "too many failed attempts")
            response = make_response(
                render_template("admin/login.html", title="Login", rate_limited=True),
                429,
            )
            response.headers["Retry-After"] = str(window_seconds)
            return response
        supplied_token = request.form.get("_csrf_token", "")
        if not hmac.compare_digest(supplied_token, session.get("csrf_token", "")):
            abort(400, "CSRF token inválido.")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        expected_user = get_setting("admin_username", "admin")
        password_hash = get_setting("admin_password_hash", "")
        if hmac.compare_digest(username, expected_user) and password_hash and check_password_hash(password_hash, password):
            limiter.clear(key)
            add_audit(request.remote_addr or "local", "auth.login", expected_user, "ok", "session login")
            session.clear()
            session["authenticated"] = True
            session["username"] = expected_user
            session["csrf_token"] = secrets.token_urlsafe(32)
            return redirect(_safe_next_url(request.args.get("next")))
        limiter.record_failure(key, window_seconds)
        add_audit(request.remote_addr or "local", "auth.login", username or "--", "failed", "invalid credentials")
        flash("Usuário ou senha inválidos.", "error")
    csrf_token()
    return render_template("admin/login.html", title="Login")


@security_bp.route("/logout", methods=["POST"])
def logout():
    supplied_token = request.form.get("_csrf_token", "")
    if not hmac.compare_digest(supplied_token, session.get("csrf_token", "")):
        abort(400, "CSRF token inválido.")
    session.clear()
    return redirect(url_for("security_bp.login"))


def init_security(app) -> None:
    app.extensions["login_limiter"] = LoginRateLimiter(
        app.config["LOGIN_MAX_CLIENTS"]
    )
    ensure_bootstrap_credentials()
    app.register_blueprint(security_bp)

    @app.context_processor
    def inject_security_context():
        return {
            "csrf_token": csrf_token,
            "current_username": session.get("username", ""),
            "pm3_mode": current_app.config.get("PM3_MODE", "ANALYSIS_ONLY"),
        }

    @app.before_request
    def enforce_authentication_and_csrf():
        endpoint = request.endpoint or ""
        if endpoint.startswith("static") or endpoint == "security_bp.login":
            return None
        if not is_authenticated():
            if request.path.startswith("/api/"):
                return jsonify({"status": "error", "message": "authentication required"}), 401
            return redirect(url_for("security_bp.login", next=request.full_path))

        # Bearer-token API clients authenticate each request and do not use cookies.
        if request.method not in SAFE_METHODS and not _is_api_token_valid():
            supplied = request.headers.get("X-CSRF-Token") or request.form.get("_csrf_token", "")
            expected = session.get("csrf_token", "")
            if not supplied or not expected or not hmac.compare_digest(str(supplied), str(expected)):
                if request.path.startswith("/api/"):
                    return jsonify({"status": "error", "message": "invalid csrf token"}), 400
                abort(400, "CSRF token inválido.")
        return None
