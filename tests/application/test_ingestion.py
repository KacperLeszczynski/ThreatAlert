from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine, func, select

from threat_alerting.application import (
    ArticleNormalizer,
    IngestionService,
    ThreatEventCorrelationService,
)
from threat_alerting.domain import ContentMode, SourceDefinition
from threat_alerting.infrastructure.db import (
    SessionFactory,
    SqlAlchemyUnitOfWork,
    create_database_engine,
    create_schema,
    create_session_factory,
    session_scope,
)
from threat_alerting.infrastructure.db.tables import (
    NewsArticleRow,
    ThreatEventArticleRow,
    ThreatEventRow,
)
from threat_alerting.infrastructure.rss import FixtureFeedTransport, RSSFeedSource
from threat_alerting.settings import Settings

FIXTURES = Path(__file__).parents[1] / "fixtures" / "rss"


@pytest.fixture
def database(tmp_path: Path) -> Iterator[tuple[Engine, SessionFactory]]:
    database_path = (tmp_path / "ingestion.db").as_posix()
    engine = create_database_engine(
        Settings(
            database_url=f"sqlite+pysqlite:///{database_path}",
            app_env="test",
            _env_file=None,
        )
    )
    create_schema(engine)
    yield engine, create_session_factory(engine)
    engine.dispose()


def fixture_source(
    fixture_name: str,
    *,
    name: str = "fixture-source",
    mode: ContentMode = ContentMode.SUMMARY_ONLY,
) -> RSSFeedSource:
    url = f"https://fixture.example.test/{fixture_name}"
    definition = SourceDefinition(
        name=name,
        url=url,
        content_mode=mode,
        trust_score=0.8,
    )
    return RSSFeedSource(
        definition,
        FixtureFeedTransport({url: (FIXTURES / fixture_name).read_bytes()}),
    )


def ingestion_service(
    sources,
    session_factory: SessionFactory,
    *,
    correlate: bool = False,
) -> IngestionService:
    return IngestionService(
        sources,
        lambda: SqlAlchemyUnitOfWork(session_factory),
        ArticleNormalizer(),
        article_correlator=ThreatEventCorrelationService() if correlate else None,
        run_id_factory=lambda: "fixture-run",
    )


def test_fixture_ingestion_twice_reports_duplicate_without_extra_row(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database
    service = ingestion_service(
        [fixture_source("security_week.xml")],
        session_factory,
    )

    first = service.run()
    second = service.run()

    assert (first.articles_seen, first.articles_new, first.duplicates_skipped) == (1, 1, 0)
    assert (second.articles_seen, second.articles_new, second.duplicates_skipped) == (1, 0, 1)
    with session_scope(session_factory) as session:
        assert session.scalar(select(func.count()).select_from(NewsArticleRow)) == 1


def test_malformed_entry_does_not_abort_source_batch(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database
    summary = ingestion_service(
        [fixture_source("mixed_entries.xml")],
        session_factory,
    ).run()

    assert summary.sources_succeeded == 1
    assert summary.articles_seen == 2
    assert summary.articles_new == 1
    assert summary.malformed_entries == 1


def test_failed_source_does_not_abort_successful_source(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database
    successful = fixture_source("security_week.xml", name="successful")
    missing_url = "https://fixture.example.test/missing"
    failed = RSSFeedSource(
        SourceDefinition(
            name="failed",
            url=missing_url,
            content_mode=ContentMode.SUMMARY_ONLY,
            trust_score=0.5,
        ),
        FixtureFeedTransport({}),
        sleep=lambda _: None,
    )

    summary = ingestion_service([failed, successful], session_factory).run()

    assert summary.sources_attempted == 2
    assert summary.sources_succeeded == 1
    assert summary.sources_failed == 1
    assert summary.articles_new == 1
    assert summary.source_failures[0].source_name == "failed"


def test_two_offline_sources_with_same_cve_create_one_corroborated_event(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database
    sources = [
        fixture_source(
            "same_cve_source_a.xml",
            name="source-a",
            mode=ContentMode.FULL_RSS,
        ),
        fixture_source(
            "same_cve_source_b.xml",
            name="source-b",
            mode=ContentMode.SUMMARY_ONLY,
        ),
    ]

    summary = ingestion_service(sources, session_factory, correlate=True).run()

    assert summary.articles_new == 2
    with session_scope(session_factory) as session:
        events = list(session.scalars(select(ThreatEventRow)))
        assert len(events) == 1
        assert events[0].event_key == "cve:CVE-2026-54321"
        assert events[0].corroborating_source_count == 2
        assert session.scalar(select(func.count()).select_from(ThreatEventArticleRow)) == 2
