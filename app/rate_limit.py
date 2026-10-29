"""Simple in-memory rate limiter for LLM-Guard."""

from collections import defaultdict, deque
from threading import Lock
from time import monotonic


_requests: dict[str, deque[float]] = defaultdict(deque)
_lock = Lock()


def check_rate_limit(
    client_key: str,
    limit: int = 60,
    window_seconds: int = 60,
) -> bool:
    """Return True when a client is within its request limit."""
    now = monotonic()
    cutoff = now - window_seconds

    with _lock:
        timestamps = _requests[client_key]

        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()

        if len(timestamps) >= limit:
            return False

        timestamps.append(now)
        return True


def reset_rate_limits() -> None:
    """Clear stored request timestamps, primarily for tests."""
    with _lock:
        _requests.clear()
