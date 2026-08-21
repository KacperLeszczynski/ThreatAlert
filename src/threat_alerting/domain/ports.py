from types import TracebackType
from typing import Protocol

from threat_alerting.domain.contracts import AggregateResult, RiskResult, StructuredLLMResult
from threat_alerting.domain.enums import ContentMode, DeliveryChannel
from threat_alerting.domain.models import (
    Alert,
    AlertDelivery,
    Assessment,
    ChannelDeliveryResult,
    ClientProfile,
    EvaluationContext,
    LLMRequest,
    NewsArticle,
    RawArticle,
    ThreatEvent,
)


class NewsSource(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def content_mode(self) -> ContentMode: ...

    def fetch(self) -> list[RawArticle]: ...


class ArticleRepository(Protocol):
    def add_or_get(self, article: NewsArticle) -> tuple[NewsArticle, bool]: ...

    def list_for_event(self, event_id: int) -> list[NewsArticle]: ...


class ThreatEventRepository(Protocol):
    def get(self, event_id: int) -> ThreatEvent | None: ...

    def add_or_get(self, event: ThreatEvent) -> tuple[ThreatEvent, bool]: ...

    def link_article(self, event_id: int, article_id: int) -> bool: ...

    def update(self, event: ThreatEvent) -> ThreatEvent: ...


class ArticleCorrelator(Protocol):
    def correlate(
        self,
        article: NewsArticle,
        unit_of_work: "IngestionUnitOfWork",
    ) -> tuple[ThreatEvent, ...]: ...


class RiskEvaluator(Protocol):
    name: str

    def evaluate(self, context: EvaluationContext) -> RiskResult: ...


class LLMProvider(Protocol):
    name: str
    model: str

    def evaluate(self, request: LLMRequest) -> StructuredLLMResult: ...


class ScoreAggregator(Protocol):
    def aggregate(self, results: list[RiskResult]) -> AggregateResult: ...


class AssessmentRepository(Protocol):
    def get(self, assessment_id: int) -> Assessment | None: ...

    def get_by_event_version(self, event_id: int, assessment_version: str) -> Assessment | None: ...

    def add_or_get(self, assessment: Assessment) -> tuple[Assessment, bool]: ...


class ClientProfileRepository(Protocol):
    def get(self, profile_id: int) -> ClientProfile | None: ...

    def add(self, profile: ClientProfile) -> ClientProfile: ...

    def update(self, profile: ClientProfile) -> ClientProfile: ...

    def list_all(self) -> list[ClientProfile]: ...

    def list_enabled(self) -> list[ClientProfile]: ...


class AlertRepository(Protocol):
    def get(self, alert_id: int) -> Alert | None: ...

    def get_for_profile_assessment(self, profile_id: int, assessment_id: int) -> Alert | None: ...

    def add_or_get(self, alert: Alert) -> tuple[Alert, bool]: ...

    def update(self, alert: Alert) -> Alert: ...


class AlertDeliveryRepository(Protocol):
    def get(self, delivery_id: int) -> AlertDelivery | None: ...

    def get_for_alert(self, alert_id: int, channel: DeliveryChannel) -> AlertDelivery | None: ...

    def add_or_get(self, delivery: AlertDelivery) -> tuple[AlertDelivery, bool]: ...

    def update(self, delivery: AlertDelivery) -> AlertDelivery: ...


class AlertChannel(Protocol):
    name: DeliveryChannel

    def deliver(self, alert: Alert, profile: ClientProfile) -> ChannelDeliveryResult: ...


class IngestionUnitOfWork(Protocol):
    news_articles: ArticleRepository
    threat_events: ThreatEventRepository

    def __enter__(self) -> "IngestionUnitOfWork": ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...

    def commit(self) -> None: ...


class AssessmentUnitOfWork(IngestionUnitOfWork, Protocol):
    assessments: AssessmentRepository


class AlertUnitOfWork(AssessmentUnitOfWork, Protocol):
    client_profiles: ClientProfileRepository
    alerts: AlertRepository
    alert_deliveries: AlertDeliveryRepository
