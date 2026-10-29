"""API-key authentication helpers for LLM-Guard."""

import hmac
import os


API_KEY_HEADER = "X-API-Key"


def get_configured_api_key() -> str | None:
    """Read the API key from the environment."""
    value = os.getenv("LLM_GUARD_API_KEY", "").strip()
    return value or None


def is_valid_api_key(provided_key: str | None) -> bool:
    """Validate a supplied API key without logging secret values."""
    expected_key = get_configured_api_key()

    if not expected_key or not provided_key:
        return False

    return hmac.compare_digest(provided_key, expected_key)
