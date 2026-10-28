"""Tests for in-memory audit event storage."""

from app.logger import clear_events, get_events, log_event


def test_log_event_is_retrievable():
    clear_events()

    log_event("audit_test", request_id="test-123", status_code=403)

    events = get_events()

    assert len(events) == 1
    assert events[0]["event"] == "audit_test"
    assert events[0]["request_id"] == "test-123"
    assert events[0]["status_code"] == 403
    assert "timestamp" in events[0]


def test_events_are_returned_newest_first():
    clear_events()

    log_event("first_event")
    log_event("second_event")

    events = get_events()

    assert events[0]["event"] == "second_event"
    assert events[1]["event"] == "first_event"


def test_event_limit_is_respected():
    clear_events()

    log_event("first_event")
    log_event("second_event")
    log_event("third_event")

    events = get_events(limit=2)

    assert len(events) == 2
    assert events[0]["event"] == "third_event"
    assert events[1]["event"] == "second_event"


def test_event_store_keeps_at_most_1000_events():
    clear_events()

    for number in range(1005):
        log_event("count_test", number=number)

    events = get_events(limit=1000)

    assert len(events) == 1000
    assert events[0]["number"] == 1004
    assert events[-1]["number"] == 5

    clear_events()
