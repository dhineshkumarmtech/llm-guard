"""Tests for the LLM-Guard proxy endpoint."""

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(
    app,
    headers={"X-API-Key": "test-only-llm-guard-key"},
)


def test_proxy_endpoint() -> None:
    """Verify that the proxy forwards a prompt and returns a request ID."""
    response = client.post(
        "/proxy",
        json={"prompt": "Hello LLM"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "model": "mock-llm-v1",
        "response": "Mock LLM response to: Hello LLM",
    }
    assert "X-Request-ID" in response.headers
