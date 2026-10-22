"""Combine rule-based findings and ML predictions into a risk score."""

from typing import Any


SEVERITY_SCORES = {
    "low": 0.30,
    "medium": 0.60,
    "high": 0.85,
    "critical": 0.95,
}


def calculate_hybrid_risk(
    rule_findings: list[dict[str, Any]],
    ml_probability: float,
) -> dict[str, Any]:
    """Calculate a combined risk score from rules and ML probability."""
    if not 0.0 <= ml_probability <= 1.0:
        raise ValueError("ml_probability must be between 0.0 and 1.0")

    rule_score = max(
        (
            SEVERITY_SCORES.get(
                str(finding.get("severity", "medium")).lower(),
                0.60,
            )
            for finding in rule_findings
        ),
        default=0.0,
    )

    # Combine independent signals while retaining the strongest rule signal.
    combined_score = 1.0 - (
        (1.0 - rule_score) * (1.0 - ml_probability * 0.75)
    )

    combined_score = min(1.0, max(0.0, combined_score))

    if combined_score >= 0.85:
        risk_level = "critical"
    elif combined_score >= 0.70:
        risk_level = "high"
    elif combined_score >= 0.40:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "risk_score": round(combined_score, 4),
        "risk_level": risk_level,
        "rule_score": round(rule_score, 4),
        "ml_probability": round(ml_probability, 4),
        "rule_finding_count": len(rule_findings),
    }
