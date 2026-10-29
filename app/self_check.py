"""Basic security configuration checks for LLM-Guard."""

import os

from app.config import settings
from app.security import get_configured_api_key


def run_security_checks() -> dict:
    """Return safe status information about security configuration."""
    api_key_configured = get_configured_api_key() is not None

    try:
        rate_limit = int(os.getenv("LLM_GUARD_RATE_LIMIT", "60"))
    except ValueError:
        rate_limit = 0

    checks = [
        {
            "name": "api_key_configured",
            "passed": api_key_configured,
            "message": (
                "API key is configured."
                if api_key_configured
                else "Set LLM_GUARD_API_KEY before using protected endpoints."
            ),
        },
        {
            "name": "rate_limit_configured",
            "passed": rate_limit > 0,
            "message": (
                f"Rate limit is configured to {rate_limit} requests per window."
                if rate_limit > 0
                else "LLM_GUARD_RATE_LIMIT must be a positive integer."
            ),
        },
        {
            "name": "request_logging_enabled",
            "passed": settings.enable_request_logging,
            "message": (
                "Request logging is enabled."
                if settings.enable_request_logging
                else "Request logging is disabled."
            ),
        },
    ]

    return {
        "status": "passed" if all(item["passed"] for item in checks) else "warning",
        "checks": checks,
    }
