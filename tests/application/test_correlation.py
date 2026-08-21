from collections.abc import Iterator
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest
from sqlalchemy import Engine, func, select

from threat_alerting.application import ThreatEventCorrelationService
from threat_alerting.application.correlation import event_identities
from threat_alerting.domain import ContentMode, ContentQuality, NewsArticle
from threat_alerting.infrastructure.db import (
    SessionFactory,
    SqlAlchemyUnitOfWork,
    create_database_engine,
    create_schema,
    create_session_factory,
    session_scope,
)
from threat_alerting.infrastructure.db.tables import ThreatEventArticleRow, ThreatEventRow
from threat_alerting.settings import Settings


@pytest.fixture
def database(tmp_path: Path) -> Iterator[tuple[Engine, SessionFactory]]:
    database_path = (tmp_path / "correlation.db").as_posix()
    engine = create_database_engine(
        Settings(database_url=f"sqlite+pysqlite:///{database_path}", _env_file=None)
    )
    create_schema(engine)
    yield engine, create_session_factory(engine)
    engine.dispose()


def make_article(
    *,
    source_name: str = "source-a",
    external_id: str = "article-a",
    canonical_url: str | None = "https://example.test/advisory",
    content: str = "CVE-2026-12345 allows remote code execution.",
    published_at: datetime = datetime(2026, 8, 19, 10, 0, tzinfo=UTC),
) -> NewsArticle:
    return NewsArticle(
        source_name=source_name,
        external_id=external_id,
        canonical_url=canonical_url,
        title="Security advisory",
        content=content,
        content_mode=ContentMode.FULL_RSS,
        content_quality=ContentQuality.FULL,
        published_at=published_at,
        fetched_at=published_at,
        content_hash="a" * 64,
    )


def persist_and_correlate(
    session_factory: SessionFactory,
    article: NewsArticle,
) -> tuple[NewsArticle, tuple]:
    correlator = ThreatEventCorrelationService()
    with SqlAlchemyUnitOfWork(session_factory) as unit_of_work:
        stored, _ = unit_of_work.news_articles.add_or_get(article)
        events = correlator.correlate(stored, unit_of_work)
        unit_of_work.commit()
    return stored, events


def test_same_cve_across_sources_has_one_key_and_source_count_two(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database
    _, first_events = persist_and_correlate(session_factory, make_article())
    _, second_events = persist_and_correlate(
        session_factory,
        make_article(
            source_name="source-b",
            external_id="article-b",
            canonical_url="https://other.example.test/report",
            content="Researchers confirmed cve-2026-12345 exploitation.",
            published_at=datetime(2026, 8, 20, 9, 0, tzinfo=UTC),
        ),
    )

    assert first_events[0].event_key == second_events[0].event_key == "cve:CVE-2026-12345"
    assert second_events[0].corroborating_source_count == 2
    assert second_events[0].first_seen_at == datetime(2026, 8, 19, 10, 0, tzinfo=UTC)
    assert second_events[0].last_seen_at == datetime(2026, 8, 20, 9, 0, tzinfo=UTC)
    with session_scope(session_factory) as session:
        assert session.scalar(select(func.count()).select_from(ThreatEventRow)) == 1
        assert session.scalar(select(func.count()).select_from(ThreatEventArticleRow)) == 2


def test_multi_cve_and_repeated_mentions_create_unique_events_and_links(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database
    article, events = persist_and_correlate(
        session_factory,
        make_article(
            content=("CVE-2026-1111 and cve-2026-22222 are affected. CVE-2026-1111 is repeated.")
        ),
    )

    assert article.id is not None
    assert {event.event_key for event in events} == {
        "cve:CVE-2026-1111",
        "cve:CVE-2026-22222",
    }
    with SqlAlchemyUnitOfWork(session_factory) as unit_of_work:
        rerun_events = ThreatEventCorrelationService().correlate(article, unit_of_work)
        unit_of_work.commit()
    assert len(rerun_events) == 2
    with session_scope(session_factory) as session:
        assert session.scalar(select(func.count()).select_from(ThreatEventRow)) == 2
        assert session.scalar(select(func.count()).select_from(ThreatEventArticleRow)) == 2


def test_url_and_article_id_fallback_keys(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database
    url_article = make_article(content="No stable CVE is present.")
    identities = event_identities(url_article)
    expected_digest = sha256(url_article.canonical_url.encode()).hexdigest()

    assert identities[0][0] == f"url:{expected_digest}"
    _, url_events = persist_and_correlate(session_factory, url_article)
    assert url_events[0].event_key == f"url:{expected_digest}"

    id_article = make_article(
        external_id="article-without-url",
        canonical_url=None,
        content="No stable identifier.",
    )
    stored, id_events = persist_and_correlate(session_factory, id_article)
    assert stored.id is not None
    assert id_events[0].event_key == f"article:{stored.id}"

    with session_scope(session_factory) as session:
        assert session.scalar(select(func.count()).select_from(ThreatEventRow)) == 2
        assert session.scalar(select(func.count()).select_from(ThreatEventArticleRow)) == 2
