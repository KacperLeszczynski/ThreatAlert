import random
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

import feedparser
import httpx

from threat_alerting.domain.enums import ContentMode
from threat_alerting.domain.models import RawArticle, SourceDefinition, utc_now
from threat_alerting.infrastructure.rss.errors import PermanentFeedError, TransientFeedError
from threat_alerting.infrastructure.rss.transport import FeedTransport


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    timeout_seconds: float = 10.0
    base_delay_seconds: float = 0.5
    max_delay_seconds: float = 10.0
    jitter_ratio: float = 0.25

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        if self.timeout_seconds <= 0 or self.base_delay_seconds <= 0:
            raise ValueError("timeouts and delays must be positive")
        if self.jitter_ratio < 0:
            raise ValueError("jitter_ratio cannot be negative")


class RSSFeedSource:
    def __init__(
        self,
        definition: SourceDefinition,
        transport: FeedTransport,
        *,
        retry_policy: RetryPolicy | None = None,
        max_entries: int = 10,
        sleep: Callable[[float], None] = time.sleep,
        random_value: Callable[[], float] = random.random,
        now: Callable[[], datetime] = utc_now,
    ) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        self._definition = definition
        self._transport = transport
        self._retry_policy = retry_policy or RetryPolicy()
        self._max_entries = max_entries
        self._sleep = sleep
        self._random_value = random_value
        self._now = now

    @property
    def name(self) -> str:
        return self._definition.name

    @property
    def content_mode(self) -> ContentMode:
        return self._definition.content_mode

    def fetch(self) -> list[RawArticle]:
        url = str(self._definition.url)
        last_error: Exception | None = None

        for attempt in range(1, self._retry_policy.max_attempts + 1):
            retry_after: float | None = None
            try:
                response = self._transport.get(
                    url,
                    timeout=self._retry_policy.timeout_seconds,
                )
                if response.status_code == 429 or response.status_code >= 500:
                    retry_after = self._parse_retry_after(response.headers.get("Retry-After"))
                    raise httpx.HTTPStatusError(
                        f"transient HTTP status {response.status_code}",
                        request=response.request,
                        response=response,
                    )
                if response.status_code < 200 or response.status_code >= 300:
                    raise PermanentFeedError(f"{self.name} returned HTTP {response.status_code}")
                return self._parse(response.content)
            except PermanentFeedError:
                raise
            except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError) as error:
                last_error = error
                if attempt == self._retry_policy.max_attempts:
                    break
                self._sleep(self._retry_delay(attempt, retry_after))

        raise TransientFeedError(
            f"{self.name} failed after {self._retry_policy.max_attempts} attempts"
        ) from last_error

    def _parse(self, content: bytes) -> list[RawArticle]:
        parsed = feedparser.parse(content)
        entries = list(parsed.entries)
        if parsed.bozo and not entries:
            raise PermanentFeedError(f"{self.name} returned an invalid RSS/Atom document")

        feed_title = _optional_text(parsed.feed.get("title"))
        return [
            _raw_article_from_entry(entry, feed_title) for entry in entries[: self._max_entries]
        ]

    def _retry_delay(self, attempt: int, retry_after: float | None) -> float:
        base_delay = min(
            self._retry_policy.max_delay_seconds,
            self._retry_policy.base_delay_seconds * (2 ** (attempt - 1)),
        )
        jitter = base_delay * self._retry_policy.jitter_ratio * self._random_value()
        return max(base_delay + jitter, retry_after or 0.0)

    def _parse_retry_after(self, value: str | None) -> float | None:
        if not value:
            return None
        try:
            return max(0.0, float(value))
        except ValueError:
            try:
                retry_at = parsedate_to_datetime(value)
            except (TypeError, ValueError, OverflowError):
                return None
            if retry_at.tzinfo is None:
                retry_at = retry_at.replace(tzinfo=UTC)
            return max(0.0, (retry_at - self._now()).total_seconds())


def _raw_article_from_entry(entry: Any, feed_title: str | None) -> RawArticle:
    content_html = None
    contents = entry.get("content") or ()
    if contents:
        content_html = _optional_text(contents[0].get("value"))

    tags = [
        tag
        for tag in (_optional_text(item.get("term")) for item in entry.get("tags", ()))
        if tag is not None
    ]
    metadata: dict[str, Any] = {}
    if feed_title is not None:
        metadata["feed_title"] = feed_title
    author = _optional_text(entry.get("author"))
    if author is not None:
        metadata["author"] = author
    if tags:
        metadata["tags"] = tags

    return RawArticle(
        external_id=_optional_text(entry.get("id") or entry.get("guid")),
        url=_optional_text(entry.get("link")),
        title=_optional_text(entry.get("title")),
        content_html=content_html,
        summary_html=_optional_text(entry.get("summary") or entry.get("description")),
        published_at=_optional_text(entry.get("published") or entry.get("updated")),
        raw_metadata=metadata,
    )


def _optional_text(value: Any) -> str | None:
    return value if isinstance(value, str) else None
