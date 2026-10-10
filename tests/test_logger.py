"""Tests for structured JSON logging."""

import json
import logging

from app.logger import log_event


def test_log_event_writes_valid_json(caplog) -> None:
    """Verify that a log event is emitted as valid JSON."""
    with caplog.at_level(logging.INFO, logger="llm_guard"):
        log_event(
            "test_event",
            request_id="test-123",
            status_code=200,
        )

    matching_records = [
        record
        for record in caplog.records
        if record.name == "llm_guard"
    ]

    assert matching_records
    event = json.loads(matching_records[-1].message)
    assert event["event"] == "test_event"
    assert event["request_id"] == "test-123"
    assert event["status_code"] == 200
    assert "timestamp" in event
