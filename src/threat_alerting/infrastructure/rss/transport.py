from collections import defaultdict, deque
from collections.abc import Mapping, Sequence
from types import TracebackType
from typing import Protocol

import httpx

FixtureOutcome = httpx.Response | Exception


class FeedTransport(Protocol):
    def get(self, url: str, *, timeout: float) -> httpx.Response: ...


class HttpxFeedTransport:
    def __init__(self, client: httpx.Client | None = None) -> None:
        self._owns_client = client is None
        self._client = client or httpx.Client(
            follow_redirects=True,
            headers={"User-Agent": "threat-alerting/0.1"},
        )

    def get(self, url: str, *, timeout: float) -> httpx.Response:
        return self._client.get(url, timeout=timeout)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "HttpxFeedTransport":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


class FixtureFeedTransport:
    def __init__(
        self,
        fixtures: Mapping[str, bytes | str | Sequence[FixtureOutcome]],
    ) -> None:
        self._outcomes: dict[str, deque[FixtureOutcome]] = {}
        self.calls: dict[str, int] = defaultdict(int)
        for url, fixture in fixtures.items():
            if isinstance(fixture, (bytes, str)):
                content = fixture.encode() if isinstance(fixture, str) else fixture
                outcomes: Sequence[FixtureOutcome] = (
                    httpx.Response(200, content=content, request=httpx.Request("GET", url)),
                )
            else:
                outcomes = fixture
            if not outcomes:
                raise ValueError(f"fixture outcomes cannot be empty for {url}")
            self._outcomes[url] = deque(outcomes)

    def get(self, url: str, *, timeout: float) -> httpx.Response:
        del timeout
        self.calls[url] += 1
        if url not in self._outcomes:
            raise httpx.ConnectError(
                "fixture URL not configured", request=httpx.Request("GET", url)
            )

        outcomes = self._outcomes[url]
        outcome = outcomes.popleft() if len(outcomes) > 1 else outcomes[0]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome
