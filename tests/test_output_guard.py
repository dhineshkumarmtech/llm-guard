"""Tests for LLM response inspection and redaction."""

from app.output_guard import inspect_output, redact_output


def test_detects_email_in_output() -> None:
    """Detect an email address in an LLM response."""
    findings = inspect_output("The email is alice@example.com.")

    assert any(item["type"] == "email" for item in findings)


def test_detects_api_key_in_output() -> None:
    """Detect a synthetic API-key-like value."""
    findings = inspect_output(
        "Token: sk-abcdefghijklmnopqrstuvwxyz1234"
    )

    assert any(item["type"] == "api_key" for item in findings)


def test_detects_possible_system_prompt_disclosure() -> None:
    """Detect a common phrase indicating prompt disclosure."""
    findings = inspect_output(
        "Here is my system prompt: keep all data confidential."
    )

    assert any(
        item["type"] == "system_prompt_leakage"
        for item in findings
    )


def test_redacts_email_in_output() -> None:
    """Remove the email value from the response."""
    result = redact_output("Contact alice@example.com.")

    assert "alice@example.com" not in result
    assert "[REDACTED_EMAIL]" in result


def test_masks_possible_prompt_disclosure() -> None:
    """Replace the whole response when a disclosure phrase is detected."""
    result = redact_output(
        "Here is my system prompt: confidential instructions."
    )

    assert result == "[REDACTED_POSSIBLE_SYSTEM_PROMPT_DISCLOSURE]"
    assert "confidential instructions" not in result


def test_normal_output_has_no_findings() -> None:
    """Allow ordinary text with no detected sensitive information."""
    assert inspect_output("The weather is sunny today.") == []
