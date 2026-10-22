"""Rule-based detection for prompt injection and jailbreak attempts."""

import re
from dataclasses import dataclass

from app.firewall.normalizer import normalize_prompt


@dataclass(frozen=True)
class FirewallRule:
    """Describe one prompt-security detection rule."""

    rule_id: str
    category: str
    severity: str
    pattern: re.Pattern[str]


RULES: tuple[FirewallRule, ...] = (
    FirewallRule(
        "PI001",
        "prompt_injection",
        "high",
        re.compile(
            r"\bignore\s+(all\s+)?(previous|prior|above|preceding)\s+"
            r"(instructions|prompts|rules)\b"
        ),
    ),
    FirewallRule(
        "PI002",
        "prompt_injection",
        "high",
        re.compile(
            r"\b(disregard|override|forget)\s+(all\s+)?"
            r"(previous|prior|system|safety)\s+"
            r"(instructions|prompts|rules)\b"
        ),
    ),
    FirewallRule(
        "JB001",
        "jailbreak",
        "high",
        re.compile(r"\b(jailbreak|dan\s+mode|do\s+anything\s+now)\b"),
    ),
    FirewallRule(
        "JB002",
        "jailbreak",
        "medium",
        re.compile(
            r"\b(bypass|disable|remove)\s+(your\s+)?"
            r"(safety|content|security)\s+(filters|restrictions|rules)\b"
        ),
    ),
    FirewallRule(
        "SP001",
        "system_prompt_extraction",
        "high",
        re.compile(
            r"\b(reveal|show|print|repeat|disclose|expose)\b"
            r".{0,50}\b(system prompt|hidden instructions|"
            r"initial instructions)\b"
        ),
    ),
)


def inspect_prompt(prompt: str) -> list[dict[str, str]]:
    """Return all matching security rules for normalized prompt text."""
    normalized = normalize_prompt(prompt)
    matches: list[dict[str, str]] = []

    for rule in RULES:
        if rule.pattern.search(normalized):
            matches.append(
                {
                    "rule_id": rule.rule_id,
                    "category": rule.category,
                    "severity": rule.severity,
                }
            )

    return matches
