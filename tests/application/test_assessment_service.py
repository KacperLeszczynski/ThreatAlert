from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import Engine

from threat_alerting.application import (
    AssessmentService,
    DeterministicRiskEvaluator,
    ImpactExpert,
    RiskAssessmentGraph,
    UrgencyExpert,
)
from threat_alerting.domain import (
    AssessmentStatus,
    ContentMode,
    ContentQuality,
    LLMEvidenceQuote,
    NewsArticle,
    StructuredLLMResult,
    ThreatEvent,
)
from threat_alerting.domain.errors import TransientLLMProviderError
from threat_alerting.infrastructure.db import (
    SessionFactory,
    SqlAlchemyUnitOfWork,
    create_database_engine,
    create_schema,
    create_session_factory,
)
from threat_alerting.infrastructure.llm import FakeLLMProvider
from threat_alerting.settings import Settings

NOW = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)


@pytest.fixture
def database(tmp_path: Path) -> Iterator[tuple[Engine, SessionFactory]]:
    database_path = (tmp_path / "assessment.db").as_posix()
    settings = Settings(
        database_url=f"sqlite+pysqlite:///{database_path}",
        app_env="test",
        _env_file=None,
    )
    engine = create_database_engine(settings)
    create_schema(engine)
    yield engine, create_session_factory(engine)
    engine.dispose()


def seed_event(
    session_factory: SessionFactory,
    *,
    quality: ContentQuality = ContentQuality.FULL,
) -> ThreatEvent:
    article = NewsArticle(
        source_name="source-a",
        external_id=f"article-{quality.value}",
        canonical_url=f"https://example.test/{quality.value}",
        title="CVE-2026-12345 is under attack",
        content=(
            "The internet-facing product is actively exploited and allows remote code execution."
        ),
        content_mode=(
            ContentMode.FULL_RSS if quality is ContentQuality.FULL else ContentMode.SUMMARY_ONLY
        ),
        content_quality=quality,
        published_at=NOW,
        fetched_at=NOW,
        content_hash="a" * 64,
    )
    event = ThreatEvent(
        event_key="cve:CVE-2026-12345",
        cve_id="CVE-2026-12345",
        corroborating_source_count=1,
    )
    with SqlAlchemyUnitOfWork(session_factory) as unit_of_work:
        stored_article, _ = unit_of_work.news_articles.add_or_get(article)
        stored_event, _ = unit_of_work.threat_events.add_or_get(event)
        assert stored_article.id is not None
        assert stored_event.id is not None
        unit_of_work.threat_events.link_article(stored_event.id, stored_article.id)
        unit_of_work.commit()
    return stored_event


def fake_result(score: float, quote: str) -> StructuredLLMResult:
    return StructuredLLMResult(
        score=score,
        confidence=0.9,
        reasons=("Fixture expert reason.",),
        evidence=(LLMEvidenceQuote(quote=quote),),
    )


def service_for(
    session_factory: SessionFactory,
    provider: FakeLLMProvider,
    *,
    version: str,
) -> AssessmentService:
    expert_options = {
        "max_attempts": 2,
        "schema_max_attempts": 2,
        "backoff_base_seconds": 0.0,
        "sleeper": lambda _: None,
        "timer": lambda: 1.0,
    }
    graph = RiskAssessmentGraph(
        [
            DeterministicRiskEvaluator(now=lambda: NOW, timer=lambda: 1.0),
            ImpactExpert(provider, **expert_options),
            UrgencyExpert(provider, **expert_options),
        ]
    )
    return AssessmentService(
        lambda: SqlAlchemyUnitOfWork(session_factory),
        graph,
        assessment_version=version,
        source_trust_scores={"source-a": 0.9},
    )


def test_complete_assessment_is_aggregated_and_persisted_with_provenance(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database
    event = seed_event(session_factory)
    assert event.id is not None
    provider = FakeLLMProvider(
        {
            "impact_expert": (fake_result(0.8, "remote code execution"),),
            "urgency_expert": (fake_result(0.7, "fabricated urgent claim"),),
        }
    )

    stored = service_for(session_factory, provider, version="risk-v5").assess(event.id)

    assert stored.status is AssessmentStatus.COMPLETE
    assert len(stored.evaluator_results) == 3
    assert stored.average_score == sum(item.score for item in stored.evaluator_results) / 3
    assert stored.score_disagreement == pytest.approx(
        max(item.score for item in stored.evaluator_results)
        - min(item.score for item in stored.evaluator_results)
    )
    assert stored.assessment_version == "risk-v5"
    assert stored.prompt_versions == {
        "impact_expert": "impact-v1",
        "urgency_expert": "urgency-v1",
    }
    assert stored.model_metadata["limited_context"] is False
    assert stored.model_metadata["evaluators"]["impact_expert"]["provider"] == "fake"
    assert stored.model_metadata["evaluators"]["impact_expert"]["model"] == "fake-llm-v1"
    urgency = next(item for item in stored.evaluator_results if item.evaluator == "urgency_expert")
    assert urgency.evidence[0].verified is False

    with SqlAlchemyUnitOfWork(session_factory) as unit_of_work:
        loaded = unit_of_work.assessments.get(stored.id)
    assert loaded == stored


def test_exhausted_evaluator_persists_incomplete_assessment_without_average(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database
    event = seed_event(session_factory)
    assert event.id is not None
    provider = FakeLLMProvider(
        {"urgency_expert": (TransientLLMProviderError("provider unavailable"),)}
    )

    stored = service_for(session_factory, provider, version="risk-failure-v1").assess(event.id)

    assert stored.status is AssessmentStatus.INCOMPLETE
    assert stored.average_score is None
    assert stored.score_disagreement is None
    assert len(stored.evaluator_results) == 2
    assert any("urgency_expert" in reason for reason in stored.failure_reasons)
    assert provider.call_count("urgency_expert") == 2


def test_limited_context_is_stored_and_changes_confidence_only(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database
    event = seed_event(session_factory, quality=ContentQuality.LIMITED)
    assert event.id is not None
    provider = FakeLLMProvider()

    stored = service_for(session_factory, provider, version="limited-v1").assess(event.id)

    assert stored.status is AssessmentStatus.COMPLETE
    assert stored.content_quality is ContentQuality.LIMITED
    assert stored.model_metadata["limited_context"] is True
    impact = next(item for item in stored.evaluator_results if item.evaluator == "impact_expert")
    urgency = next(item for item in stored.evaluator_results if item.evaluator == "urgency_expert")
    assert impact.score == 0.72
    assert impact.confidence == pytest.approx(0.88 * 0.75)
    assert urgency.score == 0.68
    assert urgency.confidence == pytest.approx(0.84 * 0.75)


def test_one_full_article_makes_a_mixed_context_full(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database
    event = seed_event(session_factory, quality=ContentQuality.FULL)
    seed_event(session_factory, quality=ContentQuality.LIMITED)
    assert event.id is not None

    stored = service_for(
        session_factory,
        FakeLLMProvider(),
        version="mixed-quality-v1",
    ).assess(event.id)

    assert stored.content_quality is ContentQuality.FULL
    assert stored.model_metadata["limited_context"] is False
    impact = next(item for item in stored.evaluator_results if item.evaluator == "impact_expert")
    assert impact.confidence == 0.88
