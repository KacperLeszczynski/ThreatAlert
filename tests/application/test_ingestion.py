from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine, func, select

from threat_alerting.application import (
    ArticleNormalizer,
    IngestionService,
    ThreatEventCorrelationService,
)
from threat_alerting.domain import ContentMode, RawArticle, SourceDefinition
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
    max_immediate_assessments: int = 10,
) -> IngestionService:
    return IngestionService(
        sources,
        lambda: SqlAlchemyUnitOfWork(session_factory),
        ArticleNormalizer(),
        article_correlator=ThreatEventCorrelationService() if correlate else None,
        max_cves_for_immediate_assessment=max_immediate_assessments,
        run_id_factory=lambda: "fixture-run",
    )


class StaticNewsSource:
    content_mode = ContentMode.FULL_RSS

    def __init__(self, name: str, articles: list[RawArticle]) -> None:
        self.name = name
        self._articles = articles

    def fetch(self) -> list[RawArticle]:
        return list(self._articles)


def cve_article(external_id: str, *cves: str) -> RawArticle:
    return RawArticle(
        external_id=external_id,
        url=f"https://fixture.example.test/{external_id}",
        title=f"Advisory {external_id}",
        content_html=" ".join(cves),
        published_at="Fri, 21 Aug 2026 10:30:00 GMT",
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


def test_small_cve_roundup_assesses_every_correlated_event(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database
    cves = tuple(f"CVE-2026-{number}" for number in range(1001, 1004))
    source = StaticNewsSource("small-roundup", [cve_article("small-roundup", *cves)])

    summary = ingestion_service([source], session_factory, correlate=True).run()

    assert summary.events_created == 3
    assert summary.events_deferred == 0
    assert len(summary.created_event_ids) == 3
    assert summary.assessment_candidate_ids == summary.created_event_ids
    assert summary.deferred_event_ids == ()


def test_large_cve_roundup_persists_all_events_but_bounds_immediate_candidates(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database
    cves = tuple(f"CVE-2026-{number}" for number in range(1001, 1013))
    source = StaticNewsSource("large-roundup", [cve_article("large-roundup", *cves)])

    summary = ingestion_service(
        [source],
        session_factory,
        correlate=True,
        max_immediate_assessments=10,
    ).run()

    assert summary.events_created == 12
    assert summary.events_deferred == 2
    assert len(summary.created_event_ids) == 12
    assert len(summary.assessment_candidate_ids) == 10
    assert len(summary.deferred_event_ids) == 2
    assert set(summary.assessment_candidate_ids).isdisjoint(summary.deferred_event_ids)
    public_summary = summary.model_dump(mode="json")
    assert "created_event_ids" not in public_summary
    assert "assessment_candidate_ids" not in public_summary
    assert "deferred_event_ids" not in public_summary
    with session_scope(session_factory) as session:
        assert session.scalar(select(func.count()).select_from(ThreatEventRow)) == 12
        assert session.scalar(select(func.count()).select_from(ThreatEventArticleRow)) == 12


def test_deferred_event_is_promoted_by_a_later_focused_article(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database
    cves = tuple(f"CVE-2026-{number}" for number in range(1001, 1013))
    bulk_source = StaticNewsSource("bulk", [cve_article("bulk", *cves)])
    focused_source = StaticNewsSource("focused", [cve_article("focused", cves[-1])])

    first = ingestion_service(
        [bulk_source],
        session_factory,
        correlate=True,
        max_immediate_assessments=10,
    ).run()
    promoted_event_id = first.deferred_event_ids[-1]
    second = ingestion_service(
        [focused_source],
        session_factory,
        correlate=True,
        max_immediate_assessments=10,
    ).run()

    assert promoted_event_id in first.deferred_event_ids
    assert promoted_event_id in second.assessment_candidate_ids
    assert promoted_event_id not in second.deferred_event_ids
    with session_scope(session_factory) as session:
        assert session.scalar(select(func.count()).select_from(ThreatEventRow)) == 12
        assert session.scalar(select(func.count()).select_from(ThreatEventArticleRow)) == 13


def test_immediate_assessment_limit_must_be_positive(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database

    with pytest.raises(ValueError, match="max_cves_for_immediate_assessment must be positive"):
        ingestion_service([], session_factory, max_immediate_assessments=0)
