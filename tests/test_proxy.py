"""Tests for the LLM-Guard proxy endpoint."""

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_proxy_endpoint() -> None:
    """Verify that the proxy forwards a prompt to the mock LLM."""
    response = client.post(
        "/proxy",
        json={"prompt": "Hello LLM"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "model": "mock-llm-v1",
        "response": "Mock LLM response to: Hello LLM",
    }
