"""Tests for sensitive-data detection and redaction."""

from app.dlp.detectors import (
    inspect_sensitive_data,
    redact_sensitive_data,
)


def test_detects_email() -> None:
    """Detect an email without exposing its value."""
    findings = inspect_sensitive_data("Contact alice@example.com")

    assert {"type": "email", "count": "1"} in findings


def test_detects_phone_number() -> None:
    """Detect a phone-number-like string."""
    findings = inspect_sensitive_data("Call +1 202-555-0147")

    assert any(item["type"] == "phone" for item in findings)


def test_detects_api_key() -> None:
    """Detect a synthetic API-key-like string."""
    findings = inspect_sensitive_data(
        "Token: sk-abcdefghijklmnopqrstuvwxyz1234"
    )

    assert any(item["type"] == "api_key" for item in findings)


def test_redacts_sensitive_values() -> None:
    """Replace email and API-key-like values with placeholders."""
    prompt = (
        "Contact alice@example.com with key "
        "sk-abcdefghijklmnopqrstuvwxyz1234"
    )

    redacted = redact_sensitive_data(prompt)

    assert "alice@example.com" not in redacted
    assert "sk-abcdefghijklmnopqrstuvwxyz1234" not in redacted
    assert "[REDACTED_EMAIL]" in redacted
    assert "[REDACTED_API_KEY]" in redacted


def test_normal_text_has_no_findings() -> None:
    """Return no findings for a prompt without sensitive data."""
    assert inspect_sensitive_data("Explain photosynthesis.") == []
