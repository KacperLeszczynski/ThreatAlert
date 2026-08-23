from collections.abc import Callable, Iterable
from uuid import uuid4

from pydantic import ValidationError

from threat_alerting.application.ingestion.normalization import (
    ArticleNormalizer,
    MalformedArticleError,
)
from threat_alerting.domain.models import IngestionSummary, SourceFailure
from threat_alerting.domain.ports import ArticleCorrelator, IngestionUnitOfWork, NewsSource


class IngestionService:
    def __init__(
        self,
        sources: Iterable[NewsSource],
        unit_of_work_factory: Callable[[], IngestionUnitOfWork],
        normalizer: ArticleNormalizer,
        *,
        article_correlator: ArticleCorrelator | None = None,
        run_id_factory: Callable[[], str] = lambda: str(uuid4()),
    ) -> None:
        self._sources = tuple(sources)
        self._unit_of_work_factory = unit_of_work_factory
        self._normalizer = normalizer
        self._article_correlator = article_correlator
        self._run_id_factory = run_id_factory

    def run(self) -> IngestionSummary:
        sources_succeeded = 0
        articles_seen = 0
        articles_new = 0
        duplicates_skipped = 0
        malformed_entries = 0
        source_failures: list[SourceFailure] = []
        created_event_ids: set[int] = set()

        for source in self._sources:
            try:
                raw_articles = source.fetch()
            except Exception as error:
                source_failures.append(
                    SourceFailure(
                        source_name=source.name,
                        reason=f"{type(error).__name__}: {error}",
                    )
                )
                continue

            sources_succeeded += 1
            with self._unit_of_work_factory() as unit_of_work:
                for raw_article in raw_articles:
                    articles_seen += 1
                    try:
                        article = self._normalizer.normalize(
                            raw_article,
                            source_name=source.name,
                            content_mode=source.content_mode,
                        )
                    except (MalformedArticleError, ValidationError):
                        malformed_entries += 1
                        continue

                    stored_article, created = unit_of_work.news_articles.add_or_get(article)
                    if created:
                        articles_new += 1
                        if self._article_correlator is not None:
                            events = self._article_correlator.correlate(
                                stored_article,
                                unit_of_work,
                            )
                            created_event_ids.update(
                                event.id for event in events if event.id is not None
                            )
                    else:
                        duplicates_skipped += 1
                unit_of_work.commit()

        return IngestionSummary(
            run_id=self._run_id_factory(),
            sources_attempted=len(self._sources),
            sources_succeeded=sources_succeeded,
            sources_failed=len(source_failures),
            articles_seen=articles_seen,
            articles_new=articles_new,
            duplicates_skipped=duplicates_skipped,
            malformed_entries=malformed_entries,
            source_failures=tuple(source_failures),
            created_event_ids=tuple(sorted(created_event_ids)),
        )
