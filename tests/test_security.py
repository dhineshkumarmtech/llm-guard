"""Tests for API-key authentication and rate limiting."""

from fastapi.testclient import TestClient

from app.main import app
from app.rate_limit import reset_rate_limits, check_rate_limit


def test_protected_endpoint_rejects_missing_api_key(monkeypatch):
    """Requests without a key must be rejected."""
    monkeypatch.setenv("LLM_GUARD_API_KEY", "security-test-key")
    client = TestClient(app)

    response = client.get("/events")

    assert response.status_code == 401


def test_protected_endpoint_rejects_invalid_api_key(monkeypatch):
    """Requests with an incorrect key must be rejected."""
    monkeypatch.setenv("LLM_GUARD_API_KEY", "security-test-key")
    client = TestClient(app, headers={"X-API-Key": "wrong-key"})

    response = client.get("/events")

    assert response.status_code == 401


def test_protected_endpoint_accepts_valid_api_key(monkeypatch):
    """Requests with the configured key must be accepted."""
    monkeypatch.setenv("LLM_GUARD_API_KEY", "security-test-key")
    client = TestClient(app, headers={"X-API-Key": "security-test-key"})

    response = client.get("/events")

    assert response.status_code == 200
    assert "events" in response.json()


def test_protected_endpoint_fails_if_api_key_is_not_configured(monkeypatch):
    """Protected endpoints must fail closed without a configured key."""
    monkeypatch.delenv("LLM_GUARD_API_KEY", raising=False)
    client = TestClient(app)

    response = client.get("/events")

    assert response.status_code == 503


def test_health_is_public(monkeypatch):
    """The health endpoint remains accessible without an API key."""
    monkeypatch.delenv("LLM_GUARD_API_KEY", raising=False)
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200


def test_rate_limiter_blocks_excess_requests():
    """A client cannot exceed its configured request limit."""
    reset_rate_limits()

    assert check_rate_limit("test-client", limit=2, window_seconds=60)
    assert check_rate_limit("test-client", limit=2, window_seconds=60)
    assert not check_rate_limit("test-client", limit=2, window_seconds=60)

    reset_rate_limits()


def test_proxy_returns_429_when_rate_limit_is_exceeded(monkeypatch):
    """The API returns HTTP 429 when a client exceeds the proxy limit."""
    monkeypatch.setenv("LLM_GUARD_API_KEY", "security-test-key")
    monkeypatch.setenv("LLM_GUARD_RATE_LIMIT", "1")
    monkeypatch.setenv("LLM_GUARD_RATE_WINDOW_SECONDS", "60")
    reset_rate_limits()

    client = TestClient(app, headers={"X-API-Key": "security-test-key"})
    payload = {"prompt": "Explain what HTTPS is in simple terms."}

    first_response = client.post("/proxy", json=payload)
    second_response = client.post("/proxy", json=payload)

    assert first_response.status_code == 200
    assert second_response.status_code == 429
    assert second_response.headers["Retry-After"] == "60"

    reset_rate_limits()
