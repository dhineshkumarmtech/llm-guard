"""Structured JSON logging utilities for LLM-Guard."""

import json
import logging
from datetime import datetime, timezone
from typing import Any


logger = logging.getLogger("llm_guard")
logger.setLevel(logging.INFO)

if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)

logger.propagate = False


def log_event(event: str, **details: Any) -> None:
    """Write one structured JSON event to the application log."""
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **details,
    }
    logger.info(json.dumps(record, default=str))
