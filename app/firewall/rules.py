"""Rule-based detection for prompt injection and jailbreak attempts."""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class FirewallRule:
    """Describe one prompt-security detection rule."""

    rule_id: str
    category: str
    severity: str
    pattern: re.Pattern[str]


RULES: tuple[FirewallRule, ...] = (
    FirewallRule(
        rule_id="PI001",
        category="prompt_injection",
        severity="high",
        pattern=re.compile(
            r"\bignore\s+(all\s+)?(previous|prior|above|preceding)\s+"
            r"(instructions|prompts|rules)\b",
            re.IGNORECASE,
        ),
    ),
    FirewallRule(
        rule_id="PI002",
        category="prompt_injection",
        severity="high",
        pattern=re.compile(
            r"\b(disregard|override|forget)\s+(all\s+)?"
            r"(previous|prior|system|safety)\s+"
            r"(instructions|prompts|rules)\b",
            re.IGNORECASE,
        ),
    ),
    FirewallRule(
        rule_id="JB001",
        category="jailbreak",
        severity="high",
        pattern=re.compile(
            r"\b(jailbreak|DAN\s+mode|do\s+anything\s+now)\b",
            re.IGNORECASE,
        ),
    ),
    FirewallRule(
        rule_id="JB002",
        category="jailbreak",
        severity="medium",
        pattern=re.compile(
            r"\b(bypass|disable|remove)\s+(your\s+)?"
            r"(safety|content|security)\s+(filters|restrictions|rules)\b",
            re.IGNORECASE,
        ),
    ),
    FirewallRule(
        rule_id="SP001",
        category="system_prompt_extraction",
        severity="high",
        pattern=re.compile(
            r"\b(reveal|show|print|repeat|disclose|expose)\b"
            r".{0,50}\b(system prompt|hidden instructions|"
            r"initial instructions)\b",
            re.IGNORECASE,
        ),
    ),
)


def inspect_prompt(prompt: str) -> list[dict[str, str]]:
    """Return all matching security rules for a prompt."""
    matches: list[dict[str, str]] = []

    for rule in RULES:
        if rule.pattern.search(prompt):
            matches.append(
                {
                    "rule_id": rule.rule_id,
                    "category": rule.category,
                    "severity": rule.severity,
                }
            )

    return matches
