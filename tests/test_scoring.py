"""Tests for hybrid risk scoring."""

import pytest

from app.firewall.scoring import calculate_hybrid_risk


def test_normal_prompt_has_low_risk() -> None:
    """Low ML probability and no findings should produce low risk."""
    result = calculate_hybrid_risk([], 0.10)

    assert result["risk_level"] == "low"
    assert result["risk_score"] < 0.40
    assert result["rule_finding_count"] == 0


def test_high_ml_probability_increases_risk() -> None:
    """A high ML probability should increase the combined score."""
    result = calculate_hybrid_risk([], 0.95)

    assert result["risk_score"] > 0.70
    assert result["risk_level"] == "high"


def test_critical_rule_produces_critical_risk() -> None:
    """A critical rule finding should result in critical risk."""
    result = calculate_hybrid_risk(
        [{"rule_id": "TEST-001", "severity": "critical"}],
        0.10,
    )

    assert result["risk_level"] == "critical"
    assert result["rule_score"] == 0.95


def test_combines_rule_and_ml_signals() -> None:
    """The combined score should reflect both detection signals."""
    rules_only = calculate_hybrid_risk(
        [{"severity": "medium"}],
        0.0,
    )
    combined = calculate_hybrid_risk(
        [{"severity": "medium"}],
        0.80,
    )

    assert combined["risk_score"] > rules_only["risk_score"]
    assert combined["ml_probability"] == 0.80


def test_rejects_invalid_ml_probability() -> None:
    """ML probabilities outside zero to one must be rejected."""
    with pytest.raises(ValueError):
        calculate_hybrid_risk([], 1.5)
