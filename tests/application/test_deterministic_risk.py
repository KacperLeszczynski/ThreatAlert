from datetime import UTC, datetime, timedelta

import pytest

from threat_alerting.application import DeterministicRiskEvaluator
from threat_alerting.domain import (
    ContentMode,
    ContentQuality,
    EvaluationContext,
    NewsArticle,
    ThreatEvent,
)

NOW = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)


def context_for(
    content: str,
    *,
    age: timedelta = timedelta(hours=12),
    quality: ContentQuality = ContentQuality.FULL,
    source_count: int = 1,
) -> EvaluationContext:
    article = NewsArticle(
        id=1,
        source_name="source-a",
        external_id="article-1",
        canonical_url="https://example.test/article-1",
        title="Security report",
        content=content,
        content_mode=(
            ContentMode.FULL_RSS if quality is ContentQuality.FULL else ContentMode.SUMMARY_ONLY
        ),
        content_quality=quality,
        published_at=NOW - age,
        fetched_at=NOW,
        content_hash="a" * 64,
    )
    return EvaluationContext(
        event=ThreatEvent(
            id=1,
            event_key="cve:CVE-2026-12345",
            cve_id="CVE-2026-12345",
            corroborating_source_count=source_count,
        ),
        articles=(article,),
        source_trust_scores={"source-a": 0.9},
    )


def evaluator() -> DeterministicRiskEvaluator:
    return DeterministicRiskEvaluator(now=lambda: NOW, timer=lambda: 1.0)


def test_active_exploitation_scores_more_than_proof_of_concept() -> None:
    active = evaluator().evaluate(context_for("The flaw is actively exploited."))
    proof_of_concept = evaluator().evaluate(
        context_for("A proof-of-concept demonstration is available.")
    )

    assert active.score > proof_of_concept.score


def test_synonyms_within_one_dimension_do_not_double_count() -> None:
    single = evaluator().evaluate(context_for("The flaw is actively exploited."))
    repeated = evaluator().evaluate(
        context_for(
            "Active exploitation was confirmed; it is exploited in the wild and a PoC exists."
        )
    )

    assert repeated.score == single.score


def test_negated_exploitation_does_not_receive_full_signal() -> None:
    negated = evaluator().evaluate(
        context_for("There is no evidence of exploitation and it is not actively exploited.")
    )
    active = evaluator().evaluate(context_for("The flaw is actively exploited."))

    assert negated.score < active.score
    assert any("negated_exploitation" in reason for reason in negated.reasons)


def test_rce_impact_exceeds_denial_of_service() -> None:
    rce = evaluator().evaluate(context_for("The flaw enables remote code execution."))
    denial_of_service = evaluator().evaluate(context_for("The flaw causes denial of service."))

    assert rce.score > denial_of_service.score


@pytest.mark.parametrize(
    ("age", "expected_score"),
    [
        (timedelta(days=1), 0.2125),
        (timedelta(days=1, seconds=1), 0.1925),
        (timedelta(days=7, seconds=1), 0.1625),
        (timedelta(days=30, seconds=1), 0.1325),
        (timedelta(days=90, seconds=1), 0.1125),
    ],
)
def test_freshness_boundaries_use_injected_clock(
    age: timedelta,
    expected_score: float,
) -> None:
    result = evaluator().evaluate(context_for("No additional deterministic signals.", age=age))

    assert result.score == expected_score


def test_explicit_cvss_is_bounded_and_exposed_in_reasons() -> None:
    result = evaluator().evaluate(context_for("The advisory assigns a CVSS v3.1 9.8 score."))

    assert 0.0 <= result.score <= 1.0
    assert any("explicit_cvss" in reason for reason in result.reasons)
    assert any(evidence.quote == "CVSS v3.1 9.8" for evidence in result.evidence)


def test_result_is_bounded_explainable_and_marks_exact_evidence_verified() -> None:
    result = evaluator().evaluate(
        context_for(
            "The internet-facing product is actively exploited and allows remote code execution.",
            source_count=2,
        )
    )

    assert 0.0 <= result.score <= 1.0
    assert 0.0 <= result.confidence <= 1.0
    assert result.evaluator == "deterministic"
    assert result.reasons
    assert {"actively exploited", "remote code execution", "internet-facing"} <= {
        item.quote.lower() for item in result.evidence
    }
    assert all(item.verified for item in result.evidence)


def test_summary_only_context_reduces_confidence_not_score() -> None:
    full = evaluator().evaluate(context_for("The flaw is actively exploited."))
    limited = evaluator().evaluate(
        context_for("The flaw is actively exploited.", quality=ContentQuality.LIMITED)
    )

    assert limited.score == full.score
    assert limited.confidence < full.confidence


def test_high_and_low_risk_results_are_explainable(capsys) -> None:
    high_context = context_for(
        "CVE-2026-12345 is actively exploited against internet-facing systems "
        "and allows remote code execution.",
        age=timedelta(hours=6),
        source_count=2,
    )
    low_context = context_for(
        "There is no evidence of exploitation. The issue requires local access "
        "and may cause denial of service.",
        age=timedelta(days=120),
    )

    high = evaluator().evaluate(high_context)
    low = evaluator().evaluate(low_context)

    print("HIGH:\n", high.model_dump_json(indent=2))
    print("LOW:\n", low.model_dump_json(indent=2))

    assert high.score > low.score
    assert high.confidence >= low.confidence

    for context, result in [(high_context, high), (low_context, low)]:
        visible_text = " ".join(
            f"{article.title} {article.content}" for article in context.articles
        ).casefold()

        assert all(evidence.quote.casefold() in visible_text for evidence in result.evidence)
