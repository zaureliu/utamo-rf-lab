from __future__ import annotations

import io

import pytest

from app import create_app
from app.database.db import set_setting


@pytest.fixture()
def app():
    return create_app({"TESTING": True})


@pytest.fixture()
def authenticated_client(app):
    client = app.test_client()
    assert client.get("/login").status_code == 200
    with client.session_transaction() as session:
        csrf = session["csrf_token"]
    client.post("/login", data={"username": "admin", "password": "test-password", "_csrf_token": csrf})
    return client


def csrf(client):
    with client.session_transaction() as session:
        return session["csrf_token"]


VALID_EML = "+Sector: 0, Block: 0\r\n" + "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\r\n"


class TestExportMissingDumpIs404:
    @pytest.mark.parametrize("fmt", ["json", "html", "csv", "pdf"])
    def test_export_unknown_dump_returns_404(self, authenticated_client, fmt):
        response = authenticated_client.get(f"/card-dump/999999/export/{fmt}")
        assert response.status_code == 404


class TestApiAnalyzeInputValidation:
    def test_analyze_invalid_text_returns_400_not_500(self, authenticated_client):
        headers = {"X-CSRF-Token": csrf(authenticated_client)}
        response = authenticated_client.post(
            "/api/card-dump/analyze",
            json={"content": "isto nao e um dump valido"},
            headers=headers,
        )
        assert response.status_code == 400
        assert response.get_json()["status"] == "error"

    def test_mifare_import_invalid_text_returns_400_not_500(self, authenticated_client):
        headers = {"X-CSRF-Token": csrf(authenticated_client)}
        response = authenticated_client.post(
            "/api/mifare/import",
            json={"card_uid": "TESTUID", "dump_text": "sem blocos validos aqui"},
            headers=headers,
        )
        assert response.status_code == 400
        assert response.get_json()["status"] == "error"

    def test_analyze_valid_eml_still_works(self, authenticated_client):
        headers = {"X-CSRF-Token": csrf(authenticated_client)}
        response = authenticated_client.post(
            "/api/card-dump/analyze",
            json={"name": "audit.eml", "content": VALID_EML},
            headers=headers,
        )
        assert response.status_code == 200
        payload = response.get_json()
        assert payload["status"] == "ok"
        assert payload["dump_id"]

    def test_analyze_upload_empty_file_returns_400(self, authenticated_client):
        headers = {"X-CSRF-Token": csrf(authenticated_client)}
        response = authenticated_client.post(
            "/api/card-dump/analyze",
            data={"dump_file": (io.BytesIO(b""), "empty.bin")},
            content_type="multipart/form-data",
            headers=headers,
        )
        assert response.status_code == 400


class TestCsvFormulaInjection:
    def test_csv_neutralizes_formula_prefixes(self, authenticated_client):
        from app.rf.report_exporter import _csv_safe

        for prefix in ("=", "+", "-", "@", "\t", "\r"):
            assert _csv_safe(f"{prefix}SUM(A1)").startswith("'")
        assert _csv_safe("normal text") == "normal text"
        assert _csv_safe(None) == ""

    def test_csv_export_sanitizes_ascii_column(self, authenticated_client):
        headers = {"X-CSRF-Token": csrf(authenticated_client)}
        result = authenticated_client.post(
            "/api/card-dump/analyze",
            # Block whose ASCII rendering begins with a formula character.
            json={"name": "csvtest.eml", "content": "+Sector: 1, Block: 4\r\n" + "3D 40 3D 40 3D 40 3D 40 3D 40 3D 40 3D 40 3D 40\r\n" * 2},
            headers=headers,
        ).get_json()
        response = authenticated_client.get(f"/card-dump/{result['dump_id']}/export/csv")
        assert response.status_code == 200
        body = response.get_data(as_text=True)
        lines = [line for line in body.splitlines() if line]
        assert len(lines) > 1
        for line in lines[1:]:
            cells = line.split(",")
            for cell in cells:
                if cell.startswith(("=", "+", "@")) or (cell.startswith("-") and not cell.startswith("--")):
                    pytest.fail(f"unsanitized CSV cell: {cell!r}")


class TestOperatorPasteProvenance:
    def test_manual_parse_event_is_marked_operator_paste(self, app, authenticated_client, monkeypatch):
        recorded = {}
        from app.rf import card_dump_analyzer

        monkeypatch.setattr(card_dump_analyzer, "record_pm3_event",
                            lambda source, event_type, uid, protocol, severity, summary, payload: recorded.update(source=source))
        headers = {"X-CSRF-Token": csrf(authenticated_client)}
        response = authenticated_client.post(
            "/api/proxmark/parse-output",
            json={"output": "UID : 04 A2 B3 C4\nSAK : 08\nATQA : 00 04 magic backdoor"},
            headers=headers,
        )
        assert response.status_code == 200
        assert recorded["source"] == "operator_paste"

    def test_engine_parse_defaults_to_proxmark_output_source(self):
        from app.rf.card_dump_analyzer import parse_pm3_output

        parsed = parse_pm3_output("UID : 04 A2 B3 C4\nSAK : 08\nATQA : 00 04")
        assert parsed["event_type"]
        # default provenance remains the hardware-derived one
        from app.database.db import get_connection

        conn = get_connection()
        try:
            row = conn.execute(
                "SELECT source FROM rfid_pm3_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
        finally:
            conn.close()
        assert row["source"] == "proxmark_output"


class TestSmartScanPreFlightFailure:
    def test_preflight_exception_marks_job_failed(self, app, authenticated_client, tmp_path, monkeypatch):
        set_setting("proxmark_client_path", r"C:\ProxSpace\pm3\proxmark3.exe")
        set_setting("proxmark_port", "COM3")
        from app.rf import smart_workflow

        job_id = smart_workflow.create_smart_scan({"auto_dump": False, "read_ndef": False, "enforce_uid": True})

        def explode(*args, **kwargs):
            raise OSError("workspace indisponível")

        monkeypatch.setattr(smart_workflow, "_copy_optional_key_file", explode)
        with app.app_context():
            result = smart_workflow.run_smart_scan(job_id)
        assert result is not None
        assert result["status"] == "failed"
        assert "workspace indisponível" in (result.get("error") or "")
