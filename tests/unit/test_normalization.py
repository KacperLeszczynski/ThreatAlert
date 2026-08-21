from datetime import UTC, datetime

from threat_alerting.application.normalization import (
    ArticleNormalizer,
    canonicalize_url,
    content_hash,
)
from threat_alerting.domain import ContentMode, ContentQuality, RawArticle

FIXED_NOW = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)


def test_normalizes_html_whitespace_timestamp_and_tracking_url() -> None:
    raw = RawArticle(
        external_id="  guid-123  ",
        url=("HTTPS://Example.COM:443/advisory?utm_source=rss&b=2&a=1&fbclid=ignored#details"),
        title="  Critical   <strong>security</strong> update ",
        content_html=(
            "<p>First&nbsp; paragraph.</p><script>ignore()</script><div>Second   paragraph.</div>"
        ),
        published_at="2026-08-20T08:30:00Z",
    )

    article = ArticleNormalizer(now=lambda: FIXED_NOW).normalize(
        raw,
        source_name="fixture",
        content_mode=ContentMode.FULL_RSS,
    )

    assert article.external_id == "guid-123"
    assert article.canonical_url == "https://example.com/advisory?a=1&b=2"
    assert article.title == "Critical security update"
    assert article.content == "First paragraph. Second paragraph."
    assert article.published_at == datetime(2026, 8, 20, 8, 30, tzinfo=UTC)
    assert article.fetched_at == FIXED_NOW
    assert article.content_quality is ContentQuality.FULL


def test_canonical_url_fallback_supplies_identity() -> None:
    article = ArticleNormalizer(now=lambda: FIXED_NOW).normalize(
        RawArticle(
            url="http://Example.test:80/story?gclid=x&edition=eu#comments",
            title="Fallback identity",
            summary_html="<p>Summary body</p>",
        ),
        source_name="fixture",
        content_mode=ContentMode.SUMMARY_ONLY,
    )

    assert article.external_id is None
    assert article.canonical_url == "http://example.test/story?edition=eu"
    assert article.content_quality is ContentQuality.LIMITED


def test_content_hash_is_stable_for_equivalent_normalized_content() -> None:
    normalizer = ArticleNormalizer(now=lambda: FIXED_NOW)
    first = normalizer.normalize(
        RawArticle(
            external_id="first",
            title="Same   title",
            content_html="<p>Same <strong>body</strong></p>",
        ),
        source_name="fixture",
        content_mode=ContentMode.FULL_RSS,
    )
    second = normalizer.normalize(
        RawArticle(
            external_id="second",
            title=" Same title ",
            content_html="Same body",
        ),
        source_name="fixture",
        content_mode=ContentMode.FULL_RSS,
    )

    assert first.content_hash == second.content_hash
    assert first.content_hash == content_hash("Same title", "Same body")


def test_url_normalization_preserves_non_tracking_parameters() -> None:
    assert canonicalize_url("https://EXAMPLE.test/path?z=2&ref=front-page&z=1#top") == (
        "https://example.test/path?ref=front-page&z=1&z=2"
    )
