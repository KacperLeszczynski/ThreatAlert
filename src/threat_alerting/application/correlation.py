from datetime import UTC, datetime
from hashlib import sha256

from threat_alerting.domain.enums import EventType
from threat_alerting.domain.models import NewsArticle, ThreatEvent
from threat_alerting.domain.ports import IngestionUnitOfWork
from threat_alerting.domain.signals import extract_categories, extract_cves


class ThreatEventCorrelationService:
    def correlate(
        self,
        article: NewsArticle,
        unit_of_work: IngestionUnitOfWork,
    ) -> tuple[ThreatEvent, ...]:
        if article.id is None:
            raise ValueError("article must be persisted before correlation")

        article_timestamp = _article_timestamp(article)
        categories = extract_categories(_article_text(article))
        events: list[ThreatEvent] = []

        for event_key, event_type, cve_id in event_identities(article):
            event, _ = unit_of_work.threat_events.add_or_get(
                ThreatEvent(
                    event_key=event_key,
                    event_type=event_type,
                    cve_id=cve_id,
                    categories=categories,
                    first_seen_at=article_timestamp,
                    last_seen_at=article_timestamp,
                    corroborating_source_count=1,
                )
            )
            if event.id is None:
                raise RuntimeError("persisted threat event has no id")

            unit_of_work.threat_events.link_article(event.id, article.id)
            linked_articles = unit_of_work.news_articles.list_for_event(event.id)
            refreshed = event.model_copy(
                update={
                    "categories": _event_categories(linked_articles),
                    "first_seen_at": min(_article_timestamp(item) for item in linked_articles),
                    "last_seen_at": max(_article_timestamp(item) for item in linked_articles),
                    "corroborating_source_count": len(
                        {item.source_name for item in linked_articles}
                    ),
                }
            )
            events.append(unit_of_work.threat_events.update(refreshed))

        return tuple(events)


def event_identities(
    article: NewsArticle,
) -> tuple[tuple[str, EventType, str | None], ...]:
    cves = extract_cves(_article_text(article))
    if cves:
        return tuple((f"cve:{cve}", EventType.VULNERABILITY, cve) for cve in cves)
    if article.canonical_url:
        url_digest = sha256(article.canonical_url.encode()).hexdigest()
        return ((f"url:{url_digest}", EventType.UNKNOWN, None),)
    if article.id is None:
        raise ValueError("article ID is required for the final event fallback")
    return ((f"article:{article.id}", EventType.UNKNOWN, None),)


def _article_text(article: NewsArticle) -> str:
    return f"{article.title}\n{article.content}"


def _article_timestamp(article: NewsArticle) -> datetime:
    timestamp = article.published_at or article.fetched_at
    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=UTC)
    return timestamp.astimezone(UTC)


def _event_categories(articles: list[NewsArticle]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                category
                for article in articles
                for category in extract_categories(_article_text(article))
            }
        )
    )
