from __future__ import annotations

import pytest

from app import create_app
from app.database.db import set_setting
from app.security import LoginRateLimiter


@pytest.fixture()
def app():
    application = create_app({"TESTING": True, "WTF_CSRF_ENABLED": False})
    return application


@pytest.fixture()
def authenticated_client(app):
    client = app.test_client()
    response = client.get("/login")
    assert response.status_code == 200
    with client.session_transaction() as session:
        csrf = session["csrf_token"]
    response = client.post("/login", data={"username": "admin", "password": "test-password", "_csrf_token": csrf})
    assert response.status_code == 302
    return client


def csrf(client):
    with client.session_transaction() as session:
        return session["csrf_token"]


def test_api_requires_authentication(app):
    response = app.test_client().get("/api/status")
    assert response.status_code == 401


def test_unsafe_cookie_request_requires_csrf(authenticated_client):
    response = authenticated_client.post("/api/protocols/classify-command", json={"command": "hf search"})
    assert response.status_code == 400


def test_csrf_allows_authenticated_api_request(authenticated_client):
    response = authenticated_client.post(
        "/api/protocols/classify-command",
        json={"command": "hf search"},
        headers={"X-CSRF-Token": csrf(authenticated_client)},
    )
    assert response.status_code == 200
    assert response.get_json()["classification"]["allowed"] is True


def test_run_endpoint_ignores_request_controlled_executable(authenticated_client):
    set_setting("proxmark_client_path", "")
    set_setting("proxmark_port", "COM5")
    response = authenticated_client.post(
        "/api/proxmark/run",
        json={"command": "hf search", "client_path": "/tmp/attacker.exe", "port": "COM99"},
        headers={"X-CSRF-Token": csrf(authenticated_client)},
    )
    payload = response.get_json()
    combined = " ".join(log.get("output", "") for log in payload["result"].get("logs", []))
    assert "/tmp/attacker.exe" not in combined
    assert "COM99" not in combined


def test_application_defaults_are_hardened(app):
    assert app.config["PM3_MODE"] == "ANALYSIS_ONLY"
    assert app.config["MAX_CONTENT_LENGTH"] <= 64 * 1024 * 1024


def test_operator_api_requires_explicit_sensitive_confirmation(app, authenticated_client):
    app.config["PM3_MODE"] = "OPERATOR_LAB"
    set_setting("proxmark_client_path", "")
    set_setting("proxmark_port", "COM5")
    headers = {"X-CSRF-Token": csrf(authenticated_client)}

    response = authenticated_client.post(
        "/api/proxmark/run",
        json={"command": "hf mf autopwn", "confirm_sensitive": "false"},
        headers=headers,
    )
    assert response.status_code == 403
    assert response.get_json()["result"]["status"] == "confirmation_required"

    response = authenticated_client.post(
        "/api/proxmark/run",
        json={"command": "hf mf autopwn", "confirm_sensitive": True},
        headers=headers,
    )
    assert response.status_code == 400
    assert response.get_json()["result"]["reason"] == "validation_error"


def test_smart_scan_pages_render(authenticated_client):
    response = authenticated_client.get("/lab")
    assert response.status_code == 200
    assert "Detectar e analisar" in response.get_data(as_text=True)
    assert 'name="_csrf_token"' in response.get_data(as_text=True)
    response = authenticated_client.get("/smart-scans")
    assert response.status_code == 200


def test_smart_scan_start_is_csrf_protected_and_queues_job(authenticated_client, monkeypatch):
    set_setting("proxmark_client_path", r"C:\\ProxSpace\\pm3\\proxmark3.exe")
    set_setting("proxmark_port", "COM3")
    monkeypatch.setattr("app.routes.api.launch_smart_scan", lambda app, job_id: None)
    headers = {"X-CSRF-Token": csrf(authenticated_client)}
    response = authenticated_client.post(
        "/api/smart-scan/start",
        json={"auto_dump": True, "read_ndef": True, "enforce_uid": True},
        headers=headers,
    )
    assert response.status_code == 202
    payload = response.get_json()
    assert payload["status"] == "queued"
    assert payload["job"]["status"] == "queued"
    assert payload["job"]["options"]["port"] == "COM3"


def test_all_primary_pages_and_assets_render(authenticated_client):
    for path in ("/", "/lab", "/dumps", "/compare", "/sessions", "/smart-scans", "/protocols", "/api/status"):
        response = authenticated_client.get(path)
        assert response.status_code == 200, path
    assert authenticated_client.get("/static/css/style.css").status_code == 200
    assert authenticated_client.get("/static/js/main.js").status_code == 200


def test_strict_csp_has_no_inline_script_or_style(authenticated_client):
    response = authenticated_client.get("/")
    csp = response.headers["Content-Security-Policy"]
    assert "'unsafe-inline'" not in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp
    assert response.headers["Cross-Origin-Resource-Policy"] == "same-origin"


def test_invalid_smart_scan_limit_returns_client_error(authenticated_client):
    response = authenticated_client.get("/api/smart-scans?limit=invalid")
    assert response.status_code == 400
    assert response.get_json()["status"] == "error"


def test_production_rejects_missing_secret():
    with pytest.raises(RuntimeError, match="UTAMO_SECRET_KEY"):
        create_app({
            "TESTING": True,
            "UTAMO_ENVIRONMENT": "production",
            "SECRET_KEY": "",
            "SESSION_COOKIE_SECURE": True,
        })


def test_production_accepts_complete_secure_configuration():
    application = create_app({
        "TESTING": True,
        "UTAMO_ENVIRONMENT": "production",
        "SECRET_KEY": "a-production-secret-with-more-than-32-characters",
        "SESSION_COOKIE_SECURE": True,
        "TRUSTED_HOSTS": ["rfid.example.test"],
    })
    assert application.config["UTAMO_ENVIRONMENT"] == "production"
    assert application.config["SESSION_COOKIE_SECURE"] is True


def test_production_rejects_missing_trusted_hosts():
    with pytest.raises(RuntimeError, match="UTAMO_TRUSTED_HOSTS"):
        create_app({
            "TESTING": True,
            "UTAMO_ENVIRONMENT": "production",
            "SECRET_KEY": "a-production-secret-with-more-than-32-characters",
            "SESSION_COOKIE_SECURE": True,
            "TRUSTED_HOSTS": None,
        })


def test_login_rate_limiter_bounds_client_cardinality():
    limiter = LoginRateLimiter(max_clients=100)
    for index in range(150):
        limiter.record_failure(str(index), window_seconds=900)
    assert limiter.client_count == 100


def test_login_rate_limit_sets_retry_after(app):
    app.config["LOGIN_MAX_FAILURES"] = 1
    client = app.test_client()
    client.get("/login")
    with client.session_transaction() as login_session:
        token = login_session["csrf_token"]
    payload = {"username": "admin", "password": "wrong", "_csrf_token": token}
    assert client.post("/login", data=payload).status_code == 200
    response = client.post("/login", data=payload)
    assert response.status_code == 429
    assert response.headers["Retry-After"] == str(app.config["LOGIN_WINDOW_SECONDS"])
