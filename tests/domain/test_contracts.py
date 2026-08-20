import pytest
from pydantic import ValidationError

from threat_alerting.domain import AggregateResult, EvidenceItem, RiskResult


def make_risk_result(**overrides) -> RiskResult:
    values = {
        "evaluator": "deterministic",
        "score": 0.75,
        "confidence": 0.9,
        "reasons": ("Active exploitation reported",),
        "evidence": (
            EvidenceItem(
                quote="The vulnerability is actively exploited.",
                verified=True,
            ),
        ),
        "duration_ms": 12,
    }
    values.update(overrides)
    return RiskResult(**values)


def test_risk_result_accepts_score_boundaries() -> None:
    assert make_risk_result(score=0.0, confidence=1.0).score == 0.0
    assert make_risk_result(score=1.0, confidence=0.0).score == 1.0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("score", -0.01),
        ("score", 1.01),
        ("confidence", -0.01),
        ("confidence", 1.01),
    ],
)
def test_risk_result_rejects_values_outside_unit_interval(field: str, value: float) -> None:
    with pytest.raises(ValidationError):
        make_risk_result(**{field: value})


def test_risk_result_strips_text_and_is_immutable() -> None:
    result = make_risk_result(evaluator="  urgency_expert  ")

    assert result.evaluator == "urgency_expert"
    with pytest.raises(ValidationError):
        result.score = 0.2


def test_aggregate_result_requires_at_least_one_result() -> None:
    with pytest.raises(ValidationError):
        AggregateResult(results=(), average_score=0.0, score_disagreement=0.0)


def test_aggregate_result_accepts_valid_complete_scores() -> None:
    result = make_risk_result()

    aggregate = AggregateResult(
        results=(result,),
        average_score=result.score,
        score_disagreement=0.0,
    )

    assert aggregate.average_score == 0.75
