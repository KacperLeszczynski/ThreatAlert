import re
from collections.abc import Callable
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from hashlib import sha256
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from threat_alerting.domain.enums import ContentMode, ContentQuality
from threat_alerting.domain.models import NewsArticle, RawArticle, utc_now

WHITESPACE = re.compile(r"\s+")
TRACKING_PARAMETERS = {
    "dclid",
    "fbclid",
    "gclid",
    "igshid",
    "mc_cid",
    "mc_eid",
    "msclkid",
    "_hsenc",
    "_hsmi",
}
BLOCK_TAGS = {
    "article",
    "br",
    "div",
    "figcaption",
    "figure",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "li",
    "p",
    "section",
    "td",
    "th",
    "tr",
}


class MalformedArticleError(ValueError):
    """A feed entry cannot satisfy the normalized article contract."""


class ArticleNormalizer:
    def __init__(
        self,
        *,
        max_characters: int = 12_000,
        now: Callable[[], datetime] = utc_now,
    ) -> None:
        if max_characters < 1:
            raise ValueError("max_characters must be positive")
        self._max_characters = max_characters
        self._now = now

    def normalize(
        self,
        raw: RawArticle,
        *,
        source_name: str,
        content_mode: ContentMode,
    ) -> NewsArticle:
        title = html_to_plain_text(raw.title)
        selected_content = _select_content(raw, content_mode)
        content = html_to_plain_text(selected_content)[: self._max_characters].strip()
        external_id = raw.external_id.strip() if raw.external_id else None
        canonical_url = canonicalize_url(raw.url) if raw.url else None

        if not title:
            raise MalformedArticleError("entry title is missing")
        if not content:
            raise MalformedArticleError("entry content is missing")
        if external_id is None and canonical_url is None:
            raise MalformedArticleError("entry has neither GUID nor canonical URL")

        return NewsArticle(
            source_name=source_name,
            external_id=external_id,
            canonical_url=canonical_url,
            title=title,
            content=content,
            content_mode=content_mode,
            content_quality=(
                ContentQuality.FULL
                if content_mode is ContentMode.FULL_RSS
                else ContentQuality.LIMITED
            ),
            published_at=parse_publication_timestamp(raw.published_at),
            fetched_at=self._now(),
            content_hash=content_hash(title, content),
            raw_metadata=dict(raw.raw_metadata),
        )


class _PlainTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._ignored_depth = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        del attrs
        if tag in {"script", "style"}:
            self._ignored_depth += 1
        elif tag in BLOCK_TAGS and self._ignored_depth == 0:
            self.parts.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self._ignored_depth:
            self._ignored_depth -= 1
        elif tag in BLOCK_TAGS and self._ignored_depth == 0:
            self.parts.append(" ")

    def handle_data(self, data: str) -> None:
        if self._ignored_depth == 0:
            self.parts.append(data)


def html_to_plain_text(value: str | None) -> str:
    if not value:
        return ""
    parser = _PlainTextExtractor()
    parser.feed(value)
    parser.close()
    return collapse_whitespace("".join(parser.parts))


def collapse_whitespace(value: str) -> str:
    return WHITESPACE.sub(" ", value).strip()


def canonicalize_url(value: str) -> str:
    candidate = value.strip()
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as error:
        raise MalformedArticleError("entry URL is invalid") from error

    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise MalformedArticleError("entry URL must use HTTP or HTTPS")
    if parsed.username or parsed.password:
        raise MalformedArticleError("entry URL cannot contain credentials")

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.encode("idna").decode("ascii").lower()
    if ":" in hostname:
        hostname = f"[{hostname}]"
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = hostname if port is None or default_port else f"{hostname}:{port}"

    query_items = [
        (key, item_value)
        for key, item_value in parse_qsl(parsed.query, keep_blank_values=True)
        if not _is_tracking_parameter(key)
    ]
    query_items.sort(key=lambda item: (item[0].lower(), item[1]))
    return urlunsplit((scheme, netloc, parsed.path or "/", urlencode(query_items), ""))


def parse_publication_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    candidate = value.strip()
    try:
        parsed = parsedate_to_datetime(candidate)
    except (TypeError, ValueError, OverflowError):
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def content_hash(title: str, content: str) -> str:
    return sha256(f"{title}\n{content}".encode()).hexdigest()


def _select_content(raw: RawArticle, content_mode: ContentMode) -> str | None:
    if content_mode is ContentMode.FULL_RSS:
        return raw.content_html or raw.summary_html
    return raw.summary_html or raw.content_html


def _is_tracking_parameter(name: str) -> bool:
    normalized = name.lower()
    return normalized.startswith("utm_") or normalized in TRACKING_PARAMETERS
