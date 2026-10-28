"""Structured JSON logging and in-memory audit events for LLM-Guard."""

import json
import logging
from collections import deque
from datetime import datetime, timezone
from threading import Lock
from typing import Any


logger = logging.getLogger("llm_guard")
logger.setLevel(logging.INFO)

if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)

logger.propagate = False

# Keep only the latest 1000 events to limit memory usage.
_MAX_EVENTS = 1000
_events: deque[dict[str, Any]] = deque(maxlen=_MAX_EVENTS)
_events_lock = Lock()


def log_event(event: str, **details: Any) -> None:
    """Record one event in memory and emit it as structured JSON."""
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **details,
    }

    with _events_lock:
        _events.append(record)

    logger.info(json.dumps(record, default=str))


def get_events(limit: int = 100) -> list[dict[str, Any]]:
    """Return the newest audit events first."""
    safe_limit = max(1, min(limit, _MAX_EVENTS))

    with _events_lock:
        recent_events = list(_events)

    return recent_events[-safe_limit:][::-1]


def clear_events() -> None:
    """Clear in-memory events; primarily useful for isolated tests."""
    with _events_lock:
        _events.clear()
