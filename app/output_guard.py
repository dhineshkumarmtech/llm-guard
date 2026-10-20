"""Inspect LLM responses for sensitive data and possible prompt leakage."""

import re

from app.dlp.detectors import (
    inspect_sensitive_data,
    redact_sensitive_data,
)


LEAKAGE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:here(?:'s| is) (?:my|the) system prompt|"
        r"(?:my|the) system prompt (?:is|says)|"
        r"(?:my|the) hidden instructions (?:are|say)|"
        r"developer instructions (?:are|say))\b",
        re.IGNORECASE,
    ),
)


def inspect_output(text: str) -> list[dict[str, str]]:
    """Return findings without exposing detected sensitive values."""
    findings = inspect_sensitive_data(text)

    leakage_count = sum(
        len(pattern.findall(text))
        for pattern in LEAKAGE_PATTERNS
    )

    if leakage_count:
        findings.append(
            {
                "type": "system_prompt_leakage",
                "count": str(leakage_count),
            }
        )

    return findings


def redact_output(text: str) -> str:
    """Remove sensitive values or mask a possible prompt disclosure."""
    if any(pattern.search(text) for pattern in LEAKAGE_PATTERNS):
        return "[REDACTED_POSSIBLE_SYSTEM_PROMPT_DISCLOSURE]"

    return redact_sensitive_data(text)
