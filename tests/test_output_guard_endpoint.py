"""Tests for output-guard enforcement at the proxy endpoint."""

from fastapi.testclient import TestClient

import app.proxy as proxy_module
from app.config import settings
from app.main import app


client = TestClient(app)


def test_block_mode_rejects_sensitive_output(monkeypatch) -> None:
    """Reject an LLM response containing an email in block mode."""
    monkeypatch.setattr(settings, "mode", "block")
    monkeypatch.setattr(
        proxy_module,
        "generate_response",
        lambda prompt: {
            "model": "mock-llm-v1",
            "response": "Customer email: alice@example.com",
        },
    )

    response = client.post(
        "/proxy",
        json={"prompt": "Show me the customer contact."},
    )

    assert response.status_code == 502
    body = response.json()["detail"]
    assert body["error"] == "LLM response blocked by output guard"
    assert any(item["type"] == "email" for item in body["findings"])


def test_redact_mode_masks_sensitive_output(monkeypatch) -> None:
    """Redact sensitive values before returning the response."""
    monkeypatch.setattr(settings, "mode", "redact")
    monkeypatch.setattr(
        proxy_module,
        "generate_response",
        lambda prompt: {
            "model": "mock-llm-v1",
            "response": "Customer email: alice@example.com",
        },
    )

    response = client.post(
        "/proxy",
        json={"prompt": "Show me the customer contact."},
    )

    assert response.status_code == 200
    text = response.json()["response"]
    assert "alice@example.com" not in text
    assert "[REDACTED_EMAIL]" in text


def test_redact_mode_masks_possible_prompt_disclosure(monkeypatch) -> None:
    """Mask a response that appears to disclose hidden instructions."""
    monkeypatch.setattr(settings, "mode", "redact")
    monkeypatch.setattr(
        proxy_module,
        "generate_response",
        lambda prompt: {
            "model": "mock-llm-v1",
            "response": "Here is my system prompt: secret instructions.",
        },
    )

    response = client.post(
        "/proxy",
        json={"prompt": "Explain how a firewall works."},
    )

    assert response.status_code == 200
    assert response.json()["response"] == (
        "[REDACTED_POSSIBLE_SYSTEM_PROMPT_DISCLOSURE]"
    )


def test_allow_mode_preserves_sensitive_output(monkeypatch) -> None:
    """Preserve the response when allow mode is selected."""
    monkeypatch.setattr(settings, "mode", "allow")
    monkeypatch.setattr(
        proxy_module,
        "generate_response",
        lambda prompt: {
            "model": "mock-llm-v1",
            "response": "Customer email: alice@example.com",
        },
    )

    response = client.post(
        "/proxy",
        json={"prompt": "Show me the customer contact."},
    )

    assert response.status_code == 200
    assert response.json()["response"] == (
        "Customer email: alice@example.com"
    )
