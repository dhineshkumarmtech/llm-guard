"""Central configuration settings for LLM-Guard."""

from typing import Literal

from pydantic import BaseModel


class GuardConfig(BaseModel):
    """Store runtime settings for the prompt firewall."""

    mode: Literal["allow", "redact", "block"] = "block"
    risk_threshold: float = 0.7
    enable_request_logging: bool = True


# Shared default settings used by the application.
settings = GuardConfig()
