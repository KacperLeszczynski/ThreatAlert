from dataclasses import dataclass
from datetime import UTC, datetime

from threat_alerting.application import ArithmeticMeanAggregator, RiskAssessmentGraph
from threat_alerting.domain import (
    ContentMode,
    ContentQuality,
    EvaluationContext,
    NewsArticle,
    RiskResult,
    ThreatEvent,
)


@dataclass
class StubEvaluator:
    name: str
    score: float
    failure: Exception | None = None

    def evaluate(self, context: EvaluationContext) -> RiskResult:
        if self.failure:
            raise self.failure
        return RiskResult(
            evaluator=self.name,
            score=self.score,
            confidence=0.9,
            reasons=(f"{self.name} reason",),
        )


def context() -> EvaluationContext:
    now = datetime(2026, 8, 20, tzinfo=UTC)
    return EvaluationContext(
        event=ThreatEvent(id=1, event_key="cve:CVE-2026-12345"),
        articles=(
            NewsArticle(
                id=1,
                source_name="source-a",
                external_id="article-1",
                title="Security advisory",
                content="A vulnerability was reported.",
                content_mode=ContentMode.FULL_RSS,
                content_quality=ContentQuality.FULL,
                fetched_at=now,
                content_hash="a" * 64,
            ),
        ),
    )


def test_graph_fans_out_to_three_evaluators_and_aggregates_exactly() -> None:
    graph = RiskAssessmentGraph(
        [
            StubEvaluator("deterministic", 0.2),
            StubEvaluator("impact_expert", 0.4),
            StubEvaluator("urgency_expert", 0.9),
        ]
    )

    outcome = graph.run(context())

    assert outcome.failure_reasons == ()
    assert outcome.aggregate_result is not None
    assert [result.evaluator for result in outcome.aggregate_result.results] == [
        "deterministic",
        "impact_expert",
        "urgency_expert",
    ]
    assert outcome.aggregate_result.average_score == 0.5
    assert outcome.aggregate_result.score_disagreement == 0.7


def test_aggregator_rejects_an_available_subset() -> None:
    aggregator = ArithmeticMeanAggregator()
    results = [
        RiskResult(evaluator="deterministic", score=0.8, confidence=0.9),
        RiskResult(evaluator="impact_expert", score=0.7, confidence=0.9),
    ]

    try:
        aggregator.aggregate(results)
    except ValueError as exc:
        assert "missing=urgency_expert" in str(exc)
    else:
        raise AssertionError("an incomplete panel must not be averaged")


def test_one_evaluator_failure_produces_no_partial_average() -> None:
    graph = RiskAssessmentGraph(
        [
            StubEvaluator("deterministic", 0.8),
            StubEvaluator("impact_expert", 0.7),
            StubEvaluator("urgency_expert", 0.6, RuntimeError("provider unavailable")),
        ]
    )

    outcome = graph.run(context())

    assert outcome.aggregate_result is None
    assert len(outcome.evaluator_results) == 2
    assert any("urgency_expert" in reason for reason in outcome.failure_reasons)
