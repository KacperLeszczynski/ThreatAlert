from datetime import UTC, datetime
from typing import Any

from pydantic import Field, model_validator

from threat_alerting.domain.contracts import DomainContract, NonEmptyText, RiskResult, UnitScore
from threat_alerting.domain.enums import (
    AlertStatus,
    AssessmentStatus,
    ContentMode,
    ContentQuality,
    DeliveryChannel,
    DeliveryStatus,
    EventType,
)


def utc_now() -> datetime:
    return datetime.now(UTC)


class NewsArticle(DomainContract):
    id: int | None = None
    source_name: NonEmptyText
    external_id: NonEmptyText | None = None
    canonical_url: NonEmptyText | None = None
    title: NonEmptyText
    content: NonEmptyText
    content_mode: ContentMode
    content_quality: ContentQuality
    published_at: datetime | None = None
    fetched_at: datetime = Field(default_factory=utc_now)
    content_hash: NonEmptyText
    raw_metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def require_source_identity(self) -> "NewsArticle":
        if self.external_id is None and self.canonical_url is None:
            raise ValueError("external_id or canonical_url is required")
        return self


class ThreatEvent(DomainContract):
    id: int | None = None
    event_key: NonEmptyText
    event_type: EventType = EventType.UNKNOWN
    cve_id: NonEmptyText | None = None
    vendors: tuple[NonEmptyText, ...] = ()
    products: tuple[NonEmptyText, ...] = ()
    categories: tuple[NonEmptyText, ...] = ()
    first_seen_at: datetime = Field(default_factory=utc_now)
    last_seen_at: datetime = Field(default_factory=utc_now)
    corroborating_source_count: int = Field(default=1, ge=0)


class Assessment(DomainContract):
    id: int | None = None
    event_id: int
    assessment_version: NonEmptyText
    status: AssessmentStatus
    evaluator_results: tuple[RiskResult, ...] = ()
    average_score: UnitScore | None = None
    score_disagreement: UnitScore | None = None
    content_quality: ContentQuality
    model_metadata: dict[str, Any] = Field(default_factory=dict)
    prompt_versions: dict[str, str] = Field(default_factory=dict)
    failure_reasons: tuple[NonEmptyText, ...] = ()
    created_at: datetime = Field(default_factory=utc_now)


class ClientProfile(DomainContract):
    id: int | None = None
    name: NonEmptyText
    minimum_score: UnitScore
    vendors: tuple[NonEmptyText, ...] = ()
    products: tuple[NonEmptyText, ...] = ()
    categories: tuple[NonEmptyText, ...] = ()
    enabled: bool = True
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class Alert(DomainContract):
    id: int | None = None
    profile_id: int
    assessment_id: int
    event_id: int
    title: NonEmptyText
    summary: NonEmptyText
    average_score: UnitScore
    threshold: UnitScore
    decision_margin: float
    needs_review: bool = False
    decision_certificate: dict[str, Any] = Field(default_factory=dict)
    status: AlertStatus = AlertStatus.PENDING
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class AlertDelivery(DomainContract):
    id: int | None = None
    alert_id: int
    channel: DeliveryChannel = DeliveryChannel.IN_APP
    status: DeliveryStatus = DeliveryStatus.PENDING
    attempt_count: int = Field(default=0, ge=0)
    last_error: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    sent_at: datetime | None = None
