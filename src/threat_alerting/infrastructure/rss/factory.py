from threat_alerting.infrastructure.rss.client import RetryPolicy, RSSFeedSource
from threat_alerting.infrastructure.rss.config import load_source_definitions
from threat_alerting.infrastructure.rss.transport import FeedTransport
from threat_alerting.settings import Settings


def create_configured_rss_sources(
    settings: Settings,
    transport: FeedTransport,
) -> tuple[RSSFeedSource, ...]:
    retry_policy = RetryPolicy(
        max_attempts=settings.rss_max_attempts,
        timeout_seconds=settings.rss_timeout_seconds,
        base_delay_seconds=settings.rss_backoff_base_seconds,
    )
    definitions = load_source_definitions(settings.sources_config_path)
    return tuple(
        RSSFeedSource(
            definition,
            transport,
            retry_policy=retry_policy,
            max_entries=settings.max_articles_per_source,
        )
        for definition in definitions
    )
