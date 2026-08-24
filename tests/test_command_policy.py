from app.rf.protocol_catalog import classify_command, get_protocol, protocol_summary
from app.rf_engine.proxmark3 import _validate_command_text, executar_comando_sync


def test_analysis_only_allows_catalog_read_only():
    result = classify_command("hf mf info", "ANALYSIS_ONLY")
    assert result["allowed"] is True
    assert result["category"] == "catalog_read_only"


def test_analysis_only_blocks_unknown_and_sensitive_commands():
    assert classify_command("hf mf autopwn", "ANALYSIS_ONLY")["allowed"] is False
    assert classify_command("hf custom whatever", "ANALYSIS_ONLY")["allowed"] is False


def test_operator_mode_is_explicit_and_requires_confirmation_for_custom_commands():
    result = classify_command("hf custom whatever", "OPERATOR_LAB")
    assert result["allowed"] is True
    assert result["category"] == "custom_operator"
    assert result["requires_confirmation"] is True


def test_operator_sensitive_command_stops_before_execution_without_confirmation(monkeypatch):
    monkeypatch.setenv("UTAMO_PM3_MODE", "OPERATOR_LAB")
    result = executar_comando_sync("/not/used", "hf mf autopwn", "COM5", confirm_sensitive=False)
    assert result["status"] == "confirmation_required"
    assert result["reason"] == "sensitive_confirmation_required"


def test_shell_metacharacters_are_rejected_even_in_operator_mode():
    for command in ("hf search & whoami", "hf search | more", "hf search\nwhoami", "hf search > out.txt"):
        try:
            _validate_command_text(command)
        except ValueError:
            pass
        else:
            raise AssertionError(command)


def test_mifare_plus_profile_and_catalog_metadata_exist():
    profile = get_protocol("hf_mfp")
    assert profile
    assert "hf mfp info" in profile["safe_commands"]
    summary = protocol_summary()
    assert summary["upstream"] == "RfidResearchGroup/proxmark3"
