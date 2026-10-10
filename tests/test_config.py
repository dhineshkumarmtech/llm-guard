"""Tests for LLM-Guard configuration settings."""

import pytest
from pydantic import ValidationError

from app.config import GuardConfig


def test_default_configuration() -> None:
    """Verify that safe default configuration values are used."""
    config = GuardConfig()

    assert config.mode == "block"
    assert config.risk_threshold == 0.7
    assert config.enable_request_logging is True


@pytest.mark.parametrize("mode", ["allow", "redact", "block"])
def test_supported_modes(mode: str) -> None:
    """Verify that all three supported modes are accepted."""
    config = GuardConfig(mode=mode)

    assert config.mode == mode


def test_invalid_mode_is_rejected() -> None:
    """Verify that unsupported modes are rejected."""
    with pytest.raises(ValidationError):
        GuardConfig(mode="unsafe")
