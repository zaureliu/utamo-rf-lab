from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from app import create_app


@pytest.fixture()
def authenticated_client(tmp_path, monkeypatch):
    from app import security
    from app.database import db

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "presentation-mode.db")
    monkeypatch.setattr(security, "RUNTIME_DIR", tmp_path)
    monkeypatch.setenv("UTAMO_ADMIN_PASSWORD", "test-password")
    application = create_app({"TESTING": True, "WTF_CSRF_ENABLED": False})
    client = application.test_client()
    assert client.get("/login").status_code == 200
    with client.session_transaction() as session:
        csrf_token = session["csrf_token"]
    response = client.post(
        "/login",
        data={"username": "admin", "password": "test-password", "_csrf_token": csrf_token},
    )
    assert response.status_code == 302
    return client


def test_presentation_mode_control_and_asset_are_global(authenticated_client):
    for path in ("/", "/lab", "/dumps", "/compare", "/sessions", "/smart-scans", "/protocols"):
        response = authenticated_client.get(path)
        assert response.status_code == 200, path
        html = response.get_data(as_text=True)
        assert 'id="presentation-mode-toggle"' in html
        assert 'js/presentation-mode.js' in html

    asset = authenticated_client.get("/static/js/presentation-mode.js")
    assert asset.status_code == 200
    assert b"utamo.presentationMode" in asset.data


def test_sensitive_template_fields_use_centralized_markers():
    template_root = Path(__file__).parents[1] / "app" / "templates"
    required_markers = {
        "dump_detail.html": ('data-sensitive="uid"', 'data-sensitive="key"', 'data-sensitive="mifare-trailer"'),
        "dumps.html": ('data-sensitive="uid"',),
        "index.html": ('data-sensitive="uid"',),
        "lab.html": ('data-sensitive="uid"', "data-sensitive-text"),
        "mifare_detail.html": ('data-sensitive="uid"', 'data-sensitive="key"'),
        "session_detail.html": ('data-sensitive="uid"', "data-sensitive-text"),
        "smart_scan_detail.html": ('data-sensitive="uid"', "data-sensitive-text"),
        "smart_scans.html": ('data-sensitive="uid"',),
    }
    for template_name, markers in required_markers.items():
        source = (template_root / template_name).read_text(encoding="utf-8")
        assert all(marker in source for marker in markers), template_name


def test_masking_functions_hide_secrets_and_preserve_technical_data():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js não está disponível para validar as funções frontend.")

    asset = Path(__file__).parents[1] / "app" / "static" / "js" / "presentation-mode.js"
    script = """
const masking = require(process.argv[1]);
const input = [
  "UID: A5 DB E2 B9",
  "serial number: SN-ABC-123",
  "Key A: FFFFFFFFFFFF",
  "password=hunter2",
  "token=abc.def.ghi",
  "technology: NFC, frequency: 13.56 MHz, samples: 42"
].join(" | ");
const report = '{"block_hex": "FFFFFFFFFFFFFF078069FFFFFFFFFFFF", "is_trailer": true}';
console.log(JSON.stringify({
  masked: masking.maskSensitiveText(input),
  trailer: masking.maskMifareTrailer("FFFFFFFFFFFFFF078069FFFFFFFFFFFF"),
  report: masking.maskSensitiveText(report)
}));
"""
    completed = subprocess.run(  # noqa: S603
        [node, "-e", script, str(asset)],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    result = json.loads(completed.stdout)

    for secret in ("A5 DB E2 B9", "SN-ABC-123", "FFFFFFFFFFFF", "hunter2", "abc.def.ghi"):
        assert secret not in result["masked"]
    assert "NFC" in result["masked"]
    assert "13.56 MHz" in result["masked"]
    assert "samples: 42" in result["masked"]
    assert "FF078069" in result["trailer"]
    assert result["trailer"].count("•") == 24
    assert "FF078069" in result["report"]
    assert "FFFFFFFFFFFF" not in result["report"]


def test_dashboard_copy_and_navigation_are_compact(authenticated_client):
    response = authenticated_client.get("/")
    html = response.get_data(as_text=True)

    assert "Painel limpo" not in html
    assert "Visão geral do laboratório" in html
    for label in ("Visão geral", "Proxmark3", "Análises", "Sessões", "Protocolos", "Apresentação"):
        assert label in html


def test_frontend_avoids_polling_overlap_and_global_dom_observer():
    static_root = Path(__file__).parents[1] / "app" / "static" / "js"
    main_source = (static_root / "main.js").read_text(encoding="utf-8")
    presentation_source = (static_root / "presentation-mode.js").read_text(encoding="utf-8")

    assert "setInterval" not in main_source
    assert "AbortController" in main_source
    assert "setTimeout(poll" in main_source
    assert "MutationObserver" not in presentation_source
