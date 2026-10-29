"""Tests for DLP enforcement at the proxy endpoint."""

from fastapi.testclient import TestClient

from app.config import settings
from app.main import app


client = TestClient(
    app,
    headers={"X-API-Key": "test-only-llm-guard-key"},
)


def test_allow_mode_forwards_original_prompt(monkeypatch) -> None:
    """Allow sensitive data through when allow mode is selected."""
    monkeypatch.setattr(settings, "mode", "allow")

    response = client.post(
        "/proxy",
        json={"prompt": "Contact alice@example.com"},
    )

    assert response.status_code == 200
    assert "alice@example.com" in response.json()["response"]


def test_redact_mode_masks_sensitive_data(monkeypatch) -> None:
    """Redact sensitive values before forwarding the prompt."""
    monkeypatch.setattr(settings, "mode", "redact")

    response = client.post(
        "/proxy",
        json={"prompt": "Contact alice@example.com"},
    )

    assert response.status_code == 200
    assert "alice@example.com" not in response.json()["response"]
    assert "[REDACTED_EMAIL]" in response.json()["response"]


def test_block_mode_rejects_sensitive_data(monkeypatch) -> None:
    """Reject prompts containing sensitive data in block mode."""
    monkeypatch.setattr(settings, "mode", "block")

    response = client.post(
        "/proxy",
        json={"prompt": "Contact alice@example.com"},
    )

    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "Prompt blocked by DLP"
    assert response.json()["detail"]["findings"][0]["type"] == "email"
