"""Detect and redact sensitive data in prompts."""

import re


PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "email",
        re.compile(
            r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
            re.IGNORECASE,
        ),
    ),
    (
        "phone",
        re.compile(r"(?<!\w)(?:\+?\d[\d\s().-]{7,}\d)(?!\w)"),
    ),
    (
        "api_key",
        re.compile(
            r"\b(?:sk-[A-Za-z0-9_-]{12,}|"
            r"AKIA[A-Z0-9]{16}|"
            r"gh[pousr]_[A-Za-z0-9_]{20,}|"
            r"AIza[A-Za-z0-9_-]{30,})\b"
        ),
    ),
)


def inspect_sensitive_data(text: str) -> list[dict[str, str]]:
    """Report sensitive-data types without exposing their values."""
    findings: list[dict[str, str]] = []

    for data_type, pattern in PATTERNS:
        count = len(list(pattern.finditer(text)))
        if count:
            findings.append(
                {
                    "type": data_type,
                    "count": str(count),
                }
            )

    return findings


def redact_sensitive_data(text: str) -> str:
    """Replace detected sensitive values with safe placeholders."""
    redacted = text

    for data_type, pattern in PATTERNS:
        redacted = pattern.sub(f"[REDACTED_{data_type.upper()}]", redacted)

    return redacted
