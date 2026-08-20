from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine, func, inspect, select, text
from sqlalchemy.exc import IntegrityError

from threat_alerting.domain import (
    Alert,
    AlertDelivery,
    Assessment,
    AssessmentStatus,
    ClientProfile,
    ContentMode,
    ContentQuality,
    EventType,
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
from threat_alerting.infrastructure.db.tables import (
    AlertDeliveryRow,
    AlertRow,
    AssessmentRow,
    NewsArticleRow,
    ThreatEventArticleRow,
    ThreatEventRow,
)
from threat_alerting.settings import Settings


@pytest.fixture
def database(tmp_path: Path) -> Iterator[tuple[Engine, SessionFactory]]:
    database_path = (tmp_path / "test.db").as_posix()
    settings = Settings(
        database_url=f"sqlite+pysqlite:///{database_path}",
        app_env="test",
        _env_file=None,
    )
    engine = create_database_engine(settings)
    create_schema(engine)
    yield engine, create_session_factory(engine)
    engine.dispose()


def make_article(**overrides) -> NewsArticle:
    values = {
        "source_name": "security-week",
        "external_id": "guid-1",
        "canonical_url": "https://example.test/news/1",
        "title": "CVE update",
        "content": "A vulnerability is being actively exploited.",
        "content_mode": ContentMode.SUMMARY_ONLY,
        "content_quality": ContentQuality.LIMITED,
        "content_hash": "a" * 64,
        "raw_metadata": {"tags": ["rce", "exploitation"], "language": "en"},
    }
    values.update(overrides)
    return NewsArticle(**values)


def make_event(**overrides) -> ThreatEvent:
    values = {
        "event_key": "cve:CVE-2026-12345",
        "event_type": EventType.VULNERABILITY,
        "cve_id": "CVE-2026-12345",
        "vendors": ("acme",),
        "products": ("gateway",),
        "categories": ("rce",),
        "corroborating_source_count": 2,
    }
    values.update(overrides)
    return ThreatEvent(**values)


def persist_event(session_factory: SessionFactory) -> ThreatEvent:
    with SqlAlchemyUnitOfWork(session_factory) as unit_of_work:
        event, _ = unit_of_work.threat_events.add_or_get(make_event())
        unit_of_work.commit()
    assert event.id is not None
    return event


def persist_assessment(session_factory: SessionFactory, event_id: int) -> Assessment:
    result = RiskResult(
        evaluator="deterministic",
        score=0.8,
        confidence=0.9,
        reasons=("Active exploitation",),
        evidence=(EvidenceItem(quote="actively exploited", verified=True),),
        duration_ms=14,
    )
    assessment = Assessment(
        event_id=event_id,
        assessment_version="risk-v1",
        status=AssessmentStatus.COMPLETE,
        evaluator_results=(result,),
        average_score=0.8,
        score_disagreement=0.0,
        content_quality=ContentQuality.FULL,
        model_metadata={"provider": "fake", "models": ["fixture-v1"]},
        prompt_versions={"impact": "impact-v1"},
    )
    with SqlAlchemyUnitOfWork(session_factory) as unit_of_work:
        stored, _ = unit_of_work.assessments.add_or_get(assessment)
        unit_of_work.commit()
    assert stored.id is not None
    return stored


def test_foreign_keys_are_enabled_for_each_connection(
    database: tuple[Engine, SessionFactory],
) -> None:
    engine, session_factory = database

    for _ in range(2):
        with engine.connect() as connection:
            assert connection.scalar(text("PRAGMA foreign_keys")) == 1

    with pytest.raises(IntegrityError), session_scope(session_factory) as session:
        session.add(ThreatEventArticleRow(event_id=999, article_id=999))


def test_required_unique_constraints_exist(database: tuple[Engine, SessionFactory]) -> None:
    engine, _ = database
    expected_constraints = {
        "news_articles": {
            ("source_name", "external_id"),
            ("source_name", "canonical_url"),
        },
        "threat_events": {("event_key",)},
        "threat_event_articles": {("event_id", "article_id")},
        "assessments": {("event_id", "assessment_version")},
        "alerts": {("profile_id", "assessment_id")},
        "alert_deliveries": {("alert_id", "channel")},
    }

    inspector = inspect(engine)
    for table_name, expected_columns in expected_constraints.items():
        actual_columns = {
            tuple(constraint["column_names"])
            for constraint in inspector.get_unique_constraints(table_name)
        }
        assert expected_columns <= actual_columns


def test_unit_of_work_rolls_back_without_explicit_commit(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database

    with SqlAlchemyUnitOfWork(session_factory) as unit_of_work:
        unit_of_work.news_articles.add_or_get(make_article())

    with session_scope(session_factory) as session:
        assert session.scalar(select(func.count()).select_from(NewsArticleRow)) == 0


def test_news_article_can_be_inserted_read_and_round_trips_content_fields(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database
    article = make_article()

    with SqlAlchemyUnitOfWork(session_factory) as unit_of_work:
        stored, created = unit_of_work.news_articles.add_or_get(article)
        unit_of_work.commit()

    assert created is True
    assert stored.id is not None

    with SqlAlchemyUnitOfWork(session_factory) as unit_of_work:
        loaded = unit_of_work.news_articles.get(stored.id)

    assert loaded is not None
    assert loaded.content_mode is ContentMode.SUMMARY_ONLY
    assert loaded.content_quality is ContentQuality.LIMITED
    assert loaded.raw_metadata == article.raw_metadata


def test_duplicate_guid_and_url_fallback_are_idempotent(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database

    with SqlAlchemyUnitOfWork(session_factory) as unit_of_work:
        first, first_created = unit_of_work.news_articles.add_or_get(make_article())
        duplicate_guid, guid_created = unit_of_work.news_articles.add_or_get(
            make_article(canonical_url="https://example.test/news/renamed")
        )
        fallback, fallback_created = unit_of_work.news_articles.add_or_get(
            make_article(external_id=None, canonical_url="https://example.test/news/fallback")
        )
        duplicate_url, url_created = unit_of_work.news_articles.add_or_get(
            make_article(
                external_id=None,
                canonical_url="https://example.test/news/fallback",
                title="Changed title",
            )
        )
        unit_of_work.commit()

    assert (first_created, guid_created, fallback_created, url_created) == (
        True,
        False,
        True,
        False,
    )
    assert duplicate_guid.id == first.id
    assert duplicate_url.id == fallback.id
    with session_scope(session_factory) as session:
        assert session.scalar(select(func.count()).select_from(NewsArticleRow)) == 2


def test_event_key_and_article_links_are_unique(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database

    with SqlAlchemyUnitOfWork(session_factory) as unit_of_work:
        article, _ = unit_of_work.news_articles.add_or_get(make_article())
        event, event_created = unit_of_work.threat_events.add_or_get(make_event())
        duplicate, duplicate_created = unit_of_work.threat_events.add_or_get(make_event())
        assert article.id is not None
        assert event.id is not None
        first_link = unit_of_work.threat_events.link_article(event.id, article.id)
        duplicate_link = unit_of_work.threat_events.link_article(event.id, article.id)
        unit_of_work.commit()

    assert event_created is True
    assert duplicate_created is False
    assert duplicate.id == event.id
    assert first_link is True
    assert duplicate_link is False
    with session_scope(session_factory) as session:
        assert session.scalar(select(func.count()).select_from(ThreatEventRow)) == 1
        assert session.scalar(select(func.count()).select_from(ThreatEventArticleRow)) == 1


def test_assessment_version_and_json_fields_round_trip(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database
    event = persist_event(session_factory)
    assert event.id is not None
    assessment = persist_assessment(session_factory, event.id)

    with SqlAlchemyUnitOfWork(session_factory) as unit_of_work:
        duplicate, created = unit_of_work.assessments.add_or_get(
            assessment.model_copy(update={"id": None})
        )
        loaded_event = unit_of_work.threat_events.get(event.id)
        loaded_assessment = unit_of_work.assessments.get(assessment.id)
        unit_of_work.commit()

    assert created is False
    assert duplicate.id == assessment.id
    assert loaded_event is not None
    assert loaded_event.vendors == ("acme",)
    assert loaded_event.products == ("gateway",)
    assert loaded_event.categories == ("rce",)
    assert loaded_assessment is not None
    assert loaded_assessment.evaluator_results[0].evidence[0].verified is True
    assert loaded_assessment.model_metadata == {"provider": "fake", "models": ["fixture-v1"]}
    assert loaded_assessment.prompt_versions == {"impact": "impact-v1"}
    with session_scope(session_factory) as session:
        assert session.scalar(select(func.count()).select_from(AssessmentRow)) == 1


def test_alert_and_delivery_unique_keys_and_json_round_trip(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database
    event = persist_event(session_factory)
    assert event.id is not None
    assessment = persist_assessment(session_factory, event.id)
    assert assessment.id is not None

    profile = ClientProfile(
        name="Payments team",
        minimum_score=0.7,
        vendors=("acme",),
        products=("gateway",),
        categories=("rce", "internet-facing"),
    )
    with SqlAlchemyUnitOfWork(session_factory) as unit_of_work:
        stored_profile = unit_of_work.client_profiles.add(profile)
        unit_of_work.commit()
    assert stored_profile.id is not None

    alert = Alert(
        profile_id=stored_profile.id,
        assessment_id=assessment.id,
        event_id=event.id,
        title="Active exploitation detected",
        summary="Acme Gateway requires attention.",
        average_score=0.8,
        threshold=0.7,
        decision_margin=0.1,
        decision_certificate={"scores": [0.8], "evidence": {"verified": True}},
    )
    with SqlAlchemyUnitOfWork(session_factory) as unit_of_work:
        stored_alert, alert_created = unit_of_work.alerts.add_or_get(alert)
        duplicate_alert, duplicate_alert_created = unit_of_work.alerts.add_or_get(alert)
        unit_of_work.commit()
    assert stored_alert.id is not None

    delivery = AlertDelivery(alert_id=stored_alert.id)
    with SqlAlchemyUnitOfWork(session_factory) as unit_of_work:
        stored_delivery, delivery_created = unit_of_work.alert_deliveries.add_or_get(delivery)
        duplicate_delivery, duplicate_delivery_created = unit_of_work.alert_deliveries.add_or_get(
            delivery
        )
        loaded_profile = unit_of_work.client_profiles.get(stored_profile.id)
        loaded_alert = unit_of_work.alerts.get(stored_alert.id)
        unit_of_work.commit()

    assert (alert_created, duplicate_alert_created) == (True, False)
    assert duplicate_alert.id == stored_alert.id
    assert (delivery_created, duplicate_delivery_created) == (True, False)
    assert duplicate_delivery.id == stored_delivery.id
    assert loaded_profile is not None
    assert loaded_profile.categories == ("rce", "internet-facing")
    assert loaded_alert is not None
    assert loaded_alert.decision_certificate == alert.decision_certificate
    with session_scope(session_factory) as session:
        assert session.scalar(select(func.count()).select_from(AlertRow)) == 1
        assert session.scalar(select(func.count()).select_from(AlertDeliveryRow)) == 1


def test_each_test_gets_an_empty_database(database: tuple[Engine, SessionFactory]) -> None:
    _, session_factory = database

    with session_scope(session_factory) as session:
        assert session.scalar(select(func.count()).select_from(NewsArticleRow)) == 0
