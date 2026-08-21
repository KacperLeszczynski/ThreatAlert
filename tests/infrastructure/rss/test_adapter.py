from pathlib import Path

import httpx
import pytest

from threat_alerting.application.normalization import ArticleNormalizer
from threat_alerting.domain import ContentMode, ContentQuality, SourceDefinition
from threat_alerting.infrastructure.rss import (
    FixtureFeedTransport,
    RetryPolicy,
    RSSFeedSource,
    load_source_definitions,
)
from threat_alerting.infrastructure.rss.errors import PermanentFeedError

FIXTURES = Path(__file__).parents[2] / "fixtures" / "rss"
PROJECT_ROOT = Path(__file__).parents[3]


def source_definition(
    *,
    name: str = "fixture",
    url: str = "https://fixture.example.test/feed",
    content_mode: ContentMode = ContentMode.FULL_RSS,
) -> SourceDefinition:
    return SourceDefinition(
        name=name,
        url=url,
        content_mode=content_mode,
        trust_score=0.8,
    )


@pytest.mark.parametrize(
    ("fixture_name", "expected_id"),
    [
        ("sans_isc.xml", "sans-2026-001"),
        ("atom.xml", "urn:uuid:atom-advisory-1"),
    ],
)
def test_same_adapter_parses_rss_and_atom(fixture_name: str, expected_id: str) -> None:
    url = "https://fixture.example.test/feed"
    transport = FixtureFeedTransport({url: (FIXTURES / fixture_name).read_bytes()})
    source = RSSFeedSource(source_definition(url=url), transport)

    articles = source.fetch()

    assert len(articles) == 1
    assert articles[0].external_id == expected_id
    assert articles[0].title
    assert articles[0].published_at


def test_configuration_contains_only_the_four_accepted_sources() -> None:
    definitions = load_source_definitions(PROJECT_ROOT / "config" / "sources.yaml")

    assert [(definition.name, definition.content_mode) for definition in definitions] == [
        ("sans-isc", ContentMode.FULL_RSS),
        ("krebs-on-security", ContentMode.FULL_RSS),
        ("security-week", ContentMode.SUMMARY_ONLY),
        ("bleeping-computer", ContentMode.SUMMARY_ONLY),
    ]
    urls = {str(definition.url) for definition in definitions}
    assert "https://isc.sans.edu/rssfeed.xml" not in urls
    assert all("ncsc" not in url.lower() for url in urls)


def test_all_configured_feed_formats_use_one_adapter_and_derive_quality() -> None:
    definitions = load_source_definitions(PROJECT_ROOT / "config" / "sources.yaml")
    fixture_names = {
        "sans-isc": "sans_isc.xml",
        "krebs-on-security": "krebs_on_security.xml",
        "security-week": "security_week.xml",
        "bleeping-computer": "bleeping_computer.xml",
    }
    fixture_mapping = {
        str(definition.url): (FIXTURES / fixture_names[definition.name]).read_bytes()
        for definition in definitions
    }
    transport = FixtureFeedTransport(fixture_mapping)
    normalizer = ArticleNormalizer()

    normalized = []
    for definition in definitions:
        source = RSSFeedSource(definition, transport)
        raw_article = source.fetch()[0]
        normalized.append(
            normalizer.normalize(
                raw_article,
                source_name=source.name,
                content_mode=source.content_mode,
            )
        )

    assert [article.content_quality for article in normalized] == [
        ContentQuality.FULL,
        ContentQuality.FULL,
        ContentQuality.LIMITED,
        ContentQuality.LIMITED,
    ]
    assert all(article.content and "<" not in article.content for article in normalized)


@pytest.mark.parametrize("status_code", [429, 500, 503])
def test_transient_http_status_retries_with_retry_after(status_code: int) -> None:
    url = "https://fixture.example.test/feed"
    request = httpx.Request("GET", url)
    transport = FixtureFeedTransport(
        {
            url: [
                httpx.Response(
                    status_code,
                    headers={"Retry-After": "2"},
                    request=request,
                ),
                httpx.Response(
                    200, content=(FIXTURES / "sans_isc.xml").read_bytes(), request=request
                ),
            ]
        }
    )
    delays: list[float] = []
    source = RSSFeedSource(
        source_definition(url=url),
        transport,
        retry_policy=RetryPolicy(max_attempts=3, base_delay_seconds=0.5),
        sleep=delays.append,
        random_value=lambda: 0.0,
    )

    assert len(source.fetch()) == 1
    assert transport.calls[url] == 2
    assert delays == [2.0]


@pytest.mark.parametrize("error_type", [httpx.ConnectError, httpx.ReadTimeout])
def test_transient_transport_error_is_retried(error_type: type[Exception]) -> None:
    url = "https://fixture.example.test/feed"
    request = httpx.Request("GET", url)
    transport = FixtureFeedTransport(
        {
            url: [
                error_type("temporary transport failure", request=request),
                httpx.Response(
                    200,
                    content=(FIXTURES / "sans_isc.xml").read_bytes(),
                    request=request,
                ),
            ]
        }
    )
    source = RSSFeedSource(
        source_definition(url=url),
        transport,
        retry_policy=RetryPolicy(max_attempts=2),
        sleep=lambda _: None,
    )

    assert len(source.fetch()) == 1
    assert transport.calls[url] == 2


def test_permanent_feed_validation_error_is_not_retried() -> None:
    url = "https://fixture.example.test/feed"
    transport = FixtureFeedTransport({url: b"this is not an RSS or Atom document"})
    delays: list[float] = []
    source = RSSFeedSource(
        source_definition(url=url),
        transport,
        retry_policy=RetryPolicy(max_attempts=3),
        sleep=delays.append,
    )

    with pytest.raises(PermanentFeedError):
        source.fetch()

    assert transport.calls[url] == 1
    assert delays == []


def test_permanent_http_error_is_not_retried() -> None:
    url = "https://fixture.example.test/feed"
    request = httpx.Request("GET", url)
    transport = FixtureFeedTransport(
        {url: [httpx.Response(404, request=request), httpx.Response(200, request=request)]}
    )
    source = RSSFeedSource(
        source_definition(url=url),
        transport,
        retry_policy=RetryPolicy(max_attempts=3),
        sleep=lambda _: None,
    )

    with pytest.raises(PermanentFeedError):
        source.fetch()

    assert transport.calls[url] == 1


def test_backoff_is_exponential_and_includes_jitter() -> None:
    url = "https://fixture.example.test/feed"
    request = httpx.Request("GET", url)
    transport = FixtureFeedTransport(
        {
            url: [
                httpx.Response(500, request=request),
                httpx.Response(502, request=request),
                httpx.Response(
                    200,
                    content=(FIXTURES / "sans_isc.xml").read_bytes(),
                    request=request,
                ),
            ]
        }
    )
    delays: list[float] = []
    source = RSSFeedSource(
        source_definition(url=url),
        transport,
        retry_policy=RetryPolicy(
            max_attempts=3,
            base_delay_seconds=1.0,
            jitter_ratio=0.25,
        ),
        sleep=delays.append,
        random_value=lambda: 1.0,
    )

    assert len(source.fetch()) == 1
    assert delays == [1.25, 2.5]
