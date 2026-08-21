from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import Engine, func, select

from threat_alerting.application import (
    AlertDecisionService,
    AlertDeliveryService,
    ClientProfileService,
)
from threat_alerting.domain import (
    AlertDecisionOutcome,
    AlertStatus,
    Assessment,
    AssessmentStatus,
    ChannelDeliveryResult,
    ClientProfile,
    ClientProfileCreate,
    ContentMode,
    ContentQuality,
    DeliveryChannel,
    DeliveryStatus,
    EvidenceItem,
    NewsArticle,
    RiskResult,
    ThreatEvent,
)
from threat_alerting.infrastructure.db import (
    SessionFactory,
    SqlAlchemyUnitOfWork,
    create_database_engine,
    create_schema,
    create_session_factory,
    session_scope,
)
from threat_alerting.infrastructure.db.tables import AlertDeliveryRow, AlertRow
from threat_alerting.infrastructure.delivery import InAppAlertChannel
from threat_alerting.settings import Settings

NOW = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)


@pytest.fixture
def database(tmp_path: Path) -> Iterator[tuple[Engine, SessionFactory]]:
    database_path = (tmp_path / "alerts.db").as_posix()
    settings = Settings(
        database_url=f"sqlite+pysqlite:///{database_path}",
        app_env="test",
        _env_file=None,
    )
    engine = create_database_engine(settings)
    create_schema(engine)
    yield engine, create_session_factory(engine)
    engine.dispose()


def evaluator_result(
    evaluator: str,
    score: float,
    *,
    verified: bool = True,
) -> RiskResult:
    is_llm = evaluator != "deterministic"
    quote = "remote code execution" if verified else "fabricated evidence"
    return RiskResult(
        evaluator=evaluator,
        score=score,
        confidence=0.9,
        reasons=(f"{evaluator} fixture reason",),
        evidence=(EvidenceItem(quote=quote, verified=verified),),
        provider="fake" if is_llm else None,
        model="fake-llm-v1" if is_llm else None,
        prompt_version=f"{evaluator}-v1" if is_llm else None,
    )


def persist_case(
    session_factory: SessionFactory,
    *,
    average_score: float | None = 0.8,
    score_disagreement: float | None = 0.0,
    status: AssessmentStatus = AssessmentStatus.COMPLETE,
    results: tuple[RiskResult, ...] | None = None,
) -> tuple[ThreatEvent, Assessment]:
    article = NewsArticle(
        source_name="source-a",
        external_id="article-1",
        canonical_url="https://example.test/article-1",
        title="CVE-2026-12345 under active attack",
        content="The Acme Secure Gateway allows remote code execution.",
        content_mode=ContentMode.FULL_RSS,
        content_quality=ContentQuality.FULL,
        published_at=NOW,
        fetched_at=NOW,
        content_hash="a" * 64,
    )
    event = ThreatEvent(
        event_key="cve:CVE-2026-12345",
        cve_id="CVE-2026-12345",
        vendors=("Acme, Inc.",),
        products=("Secure Gateway",),
        categories=("active-exploitation", "rce"),
        corroborating_source_count=1,
    )
    if results is None:
        score = average_score if average_score is not None else 0.8
        results = (
            evaluator_result("deterministic", score),
            evaluator_result("impact_expert", score),
            evaluator_result("urgency_expert", score),
        )
    assessment = Assessment(
        event_id=0,
        assessment_version="stage6-v1",
        status=status,
        evaluator_results=results,
        average_score=average_score,
        score_disagreement=score_disagreement,
        content_quality=ContentQuality.FULL,
        model_metadata={"limited_context": False},
        prompt_versions={
            "impact_expert": "impact_expert-v1",
            "urgency_expert": "urgency_expert-v1",
        },
    )
    with SqlAlchemyUnitOfWork(session_factory) as unit_of_work:
        stored_article, _ = unit_of_work.news_articles.add_or_get(article)
        stored_event, _ = unit_of_work.threat_events.add_or_get(event)
        assert stored_article.id is not None
        assert stored_event.id is not None
        unit_of_work.threat_events.link_article(stored_event.id, stored_article.id)
        stored_assessment, _ = unit_of_work.assessments.add_or_get(
            assessment.model_copy(update={"event_id": stored_event.id})
        )
        unit_of_work.commit()
    return stored_event, stored_assessment


def create_profile(
    session_factory: SessionFactory,
    *,
    threshold: float = 0.7,
    **filters,
) -> ClientProfile:
    return ClientProfileService(
        lambda: SqlAlchemyUnitOfWork(session_factory),
        clock=lambda: NOW,
    ).create(
        ClientProfileCreate(
            name="Payments",
            minimum_score=threshold,
            **filters,
        )
    )


def decision_service(session_factory: SessionFactory) -> AlertDecisionService:
    return AlertDecisionService(
        lambda: SqlAlchemyUnitOfWork(session_factory),
        disagreement_review_threshold=0.40,
        borderline_margin=0.05,
        invalid_evidence_high_score_threshold=0.70,
    )


def row_count(session_factory: SessionFactory, row_type) -> int:
    with session_scope(session_factory) as session:
        return session.scalar(select(func.count()).select_from(row_type)) or 0


def test_irrelevant_profile_gets_explicit_no_alert_result(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database
    _, assessment = persist_case(session_factory)
    profile = create_profile(session_factory, vendors=("Different Vendor",))

    result = decision_service(session_factory).decide(profile.id, assessment.id)

    assert result.outcome is AlertDecisionOutcome.NO_ALERT
    assert result.reason_codes == ("profile_filter_mismatch",)
    assert result.alert is None
    assert row_count(session_factory, AlertRow) == 0


@pytest.mark.parametrize(
    ("score", "expected_reason", "expected_margin"),
    [
        (0.6, "score_below_threshold", -0.1),
        (0.7, "score_equal_to_threshold", 0.0),
    ],
)
def test_score_not_strictly_above_threshold_creates_no_alert(
    database: tuple[Engine, SessionFactory],
    score: float,
    expected_reason: str,
    expected_margin: float,
) -> None:
    _, session_factory = database
    _, assessment = persist_case(session_factory, average_score=score)
    profile = create_profile(session_factory, threshold=0.7)

    result = decision_service(session_factory).decide(profile.id, assessment.id)

    assert result.outcome is AlertDecisionOutcome.NO_ALERT
    assert expected_reason in result.reason_codes
    assert result.decision_margin == expected_margin
    assert row_count(session_factory, AlertRow) == 0


def test_score_above_threshold_creates_one_pending_alert_with_margin(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database
    _, assessment = persist_case(session_factory, average_score=0.8)
    profile = create_profile(session_factory, threshold=0.7)

    result = decision_service(session_factory).decide(profile.id, assessment.id)

    assert result.outcome is AlertDecisionOutcome.ALERT
    assert result.alert_created is True
    assert result.alert is not None
    assert result.alert.status is AlertStatus.PENDING
    assert result.decision_margin == 0.1
    assert row_count(session_factory, AlertRow) == 1


def test_review_flags_and_certificate_include_complete_decision_provenance(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database
    results = (
        evaluator_result("deterministic", 0.6),
        evaluator_result("impact_expert", 0.8, verified=False),
        evaluator_result("urgency_expert", 1.0),
    )
    _, assessment = persist_case(
        session_factory,
        average_score=0.8,
        score_disagreement=0.4,
        results=results,
    )
    profile = create_profile(
        session_factory,
        threshold=0.78,
        categories=("Active Exploitation",),
    )

    result = decision_service(session_factory).decide(profile.id, assessment.id)

    assert result.needs_review is True
    assert set(result.review_reasons) == {
        "high_score_disagreement",
        "borderline_threshold_margin",
        "invalid_high_score_evidence:impact_expert",
    }
    certificate = result.decision_certificate
    assert certificate["assessment"]["scores"] == {
        "deterministic": 0.6,
        "impact_expert": 0.8,
        "urgency_expert": 1.0,
    }
    assert certificate["assessment"]["score_disagreement"] == 0.4
    assert certificate["assessment"]["evidence"][1]["verified"] is False
    assert certificate["assessment"]["provenance"]["evaluators"]["impact_expert"] == {
        "confidence": 0.9,
        "provider": "fake",
        "model": "fake-llm-v1",
        "prompt_version": "impact_expert-v1",
        "attempt_count": 1,
        "duration_ms": 0,
    }
    assert certificate["profile"]["matched_by"] == ["category:active_exploitation"]
    assert certificate["decision"] == {
        "outcome": "alert",
        "threshold": 0.78,
        "margin": 0.02,
        "reason_codes": ["profile_matched", "score_above_threshold"],
        "review_reasons": list(result.review_reasons),
        "needs_review": True,
    }


def test_incomplete_assessment_never_reaches_alert_creation(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database
    _, assessment = persist_case(
        session_factory,
        status=AssessmentStatus.INCOMPLETE,
        average_score=None,
        score_disagreement=None,
        results=(evaluator_result("deterministic", 0.9),),
    )
    profile = create_profile(session_factory)

    result = decision_service(session_factory).decide(profile.id, assessment.id)

    assert result.outcome is AlertDecisionOutcome.NO_ALERT
    assert result.reason_codes == ("assessment_incomplete",)
    assert row_count(session_factory, AlertRow) == 0


class ObservingChannel:
    name = DeliveryChannel.IN_APP

    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory
        self.observed_states = None

    def deliver(self, alert, profile) -> ChannelDeliveryResult:
        with session_scope(self._session_factory) as session:
            alert_row = session.get(AlertRow, alert.id)
            delivery_row = session.scalar(
                select(AlertDeliveryRow).where(AlertDeliveryRow.alert_id == alert.id)
            )
            self.observed_states = (alert_row.status, delivery_row.status)
        return ChannelDeliveryResult(succeeded=True)


class FailingChannel:
    name = DeliveryChannel.IN_APP

    def deliver(self, alert, profile) -> ChannelDeliveryResult:
        return ChannelDeliveryResult(succeeded=False, error="controlled delivery failure")


def pending_alert(session_factory: SessionFactory):
    _, assessment = persist_case(session_factory)
    profile = create_profile(session_factory)
    decision = decision_service(session_factory).decide(profile.id, assessment.id)
    assert decision.alert is not None
    return decision.alert


def test_alert_and_delivery_are_pending_before_channel_attempt(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database
    alert = pending_alert(session_factory)
    channel = ObservingChannel(session_factory)

    AlertDeliveryService(
        lambda: SqlAlchemyUnitOfWork(session_factory),
        clock=lambda: NOW,
    ).deliver(alert.id, channel)

    assert channel.observed_states == (AlertStatus.PENDING, DeliveryStatus.PENDING)


def test_successful_in_app_delivery_marks_alert_and_delivery_sent(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database
    alert = pending_alert(session_factory)

    result = AlertDeliveryService(
        lambda: SqlAlchemyUnitOfWork(session_factory),
        clock=lambda: NOW,
    ).deliver(alert.id, InAppAlertChannel())

    assert result.attempted is True
    assert result.alert.status is AlertStatus.SENT
    assert result.delivery.status is DeliveryStatus.SENT
    assert result.delivery.attempt_count == 1
    assert result.delivery.sent_at == NOW


def test_failed_delivery_preserves_alert_and_failure_details(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database
    alert = pending_alert(session_factory)

    result = AlertDeliveryService(
        lambda: SqlAlchemyUnitOfWork(session_factory),
        clock=lambda: NOW,
    ).deliver(alert.id, FailingChannel())

    assert result.alert.id == alert.id
    assert result.alert.status is AlertStatus.FAILED
    assert result.delivery.status is DeliveryStatus.FAILED
    assert result.delivery.attempt_count == 1
    assert result.delivery.last_error == "controlled delivery failure"


def test_decision_and_delivery_rerun_is_idempotent(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database
    _, assessment = persist_case(session_factory)
    profile = create_profile(session_factory)
    decisions = decision_service(session_factory)

    first_decision = decisions.decide(profile.id, assessment.id)
    second_decision = decisions.decide(profile.id, assessment.id)
    assert first_decision.alert is not None
    assert second_decision.alert is not None
    assert first_decision.alert.id == second_decision.alert.id
    assert first_decision.alert_created is True
    assert second_decision.alert_created is False

    deliveries = AlertDeliveryService(
        lambda: SqlAlchemyUnitOfWork(session_factory),
        clock=lambda: NOW,
    )
    first_delivery = deliveries.deliver(first_decision.alert.id, InAppAlertChannel())
    second_delivery = deliveries.deliver(first_decision.alert.id, InAppAlertChannel())

    assert first_delivery.attempted is True
    assert second_delivery.attempted is False
    assert row_count(session_factory, AlertRow) == 1
    assert row_count(session_factory, AlertDeliveryRow) == 1
