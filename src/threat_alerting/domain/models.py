from datetime import UTC, datetime
from typing import Any

from pydantic import Field, HttpUrl, model_validator

from threat_alerting.domain.contracts import (
    DomainContract,
    NonEmptyText,
    RiskResult,
    UnitScore,
)
from threat_alerting.domain.enums import (
    AlertDecisionOutcome,
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


class RawArticle(DomainContract):
    external_id: str | None = None
    url: str | None = None
    title: str | None = None
    content_html: str | None = None
    summary_html: str | None = None
    published_at: str | None = None
    raw_metadata: dict[str, Any] = Field(default_factory=dict)


class SourceDefinition(DomainContract):
    name: NonEmptyText
    url: HttpUrl
    content_mode: ContentMode
    trust_score: UnitScore
    enabled: bool = True


class SourceFailure(DomainContract):
    source_name: NonEmptyText
    reason: NonEmptyText


class IngestionSummary(DomainContract):
    run_id: NonEmptyText
    sources_attempted: int = Field(default=0, ge=0)
    sources_succeeded: int = Field(default=0, ge=0)
    sources_failed: int = Field(default=0, ge=0)
    articles_seen: int = Field(default=0, ge=0)
    articles_new: int = Field(default=0, ge=0)
    duplicates_skipped: int = Field(default=0, ge=0)
    malformed_entries: int = Field(default=0, ge=0)
    events_created: int = Field(default=0, ge=0)
    events_deferred: int = Field(default=0, ge=0)
    source_failures: tuple[SourceFailure, ...] = ()
    created_event_ids: tuple[int, ...] = Field(default=(), exclude=True)
    assessment_candidate_ids: tuple[int, ...] = Field(default=(), exclude=True)
    deferred_event_ids: tuple[int, ...] = Field(default=(), exclude=True)


class PipelineRunSummary(DomainContract):
    run_id: NonEmptyText
    sources_attempted: int = Field(default=0, ge=0)
    sources_succeeded: int = Field(default=0, ge=0)
    sources_failed: int = Field(default=0, ge=0)
    articles_seen: int = Field(default=0, ge=0)
    articles_new: int = Field(default=0, ge=0)
    duplicates_skipped: int = Field(default=0, ge=0)
    malformed_entries: int = Field(default=0, ge=0)
    events_created: int = Field(default=0, ge=0)
    events_deferred: int = Field(default=0, ge=0)
    assessments_complete: int = Field(default=0, ge=0)
    assessments_incomplete: int = Field(default=0, ge=0)
    no_alert_decisions: int = Field(default=0, ge=0)
    alerts_created: int = Field(default=0, ge=0)
    alerts_delivered: int = Field(default=0, ge=0)
    alerts_failed: int = Field(default=0, ge=0)
    source_failures: tuple[SourceFailure, ...] = ()


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


class EvaluationContext(DomainContract):
    event: ThreatEvent
    articles: tuple[NewsArticle, ...] = Field(min_length=1)
    source_trust_scores: dict[str, UnitScore] = Field(default_factory=dict)


class LLMRequest(DomainContract):
    evaluator: NonEmptyText
    prompt_version: NonEmptyText
    system_instructions: NonEmptyText
    untrusted_content: NonEmptyText
    repair_instruction: NonEmptyText | None = None


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

    @model_validator(mode="after")
    def validate_completion_fields(self) -> "Assessment":
        complete = self.status is AssessmentStatus.COMPLETE
        if complete and (self.average_score is None or self.score_disagreement is None):
            raise ValueError("complete assessment requires aggregate scores")
        if not complete and (self.average_score is not None or self.score_disagreement is not None):
            raise ValueError("non-complete assessment cannot contain aggregate scores")
        return self


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


class ClientProfileCreate(DomainContract):
    name: NonEmptyText
    minimum_score: UnitScore
    vendors: tuple[NonEmptyText, ...] = ()
    products: tuple[NonEmptyText, ...] = ()
    categories: tuple[NonEmptyText, ...] = ()
    enabled: bool = True


class ClientProfileUpdate(DomainContract):
    name: NonEmptyText | None = None
    minimum_score: UnitScore | None = None
    vendors: tuple[NonEmptyText, ...] | None = None
    products: tuple[NonEmptyText, ...] | None = None
    categories: tuple[NonEmptyText, ...] | None = None
    enabled: bool | None = None


class ProfileMatchResult(DomainContract):
    matched: bool
    matched_by: tuple[NonEmptyText, ...] = ()
    reason_codes: tuple[NonEmptyText, ...] = ()


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


class AlertDecisionResult(DomainContract):
    outcome: AlertDecisionOutcome
    profile_id: int
    assessment_id: int
    average_score: UnitScore | None = None
    threshold: UnitScore
    decision_margin: float | None = None
    matched_by: tuple[NonEmptyText, ...] = ()
    reason_codes: tuple[NonEmptyText, ...] = ()
    review_reasons: tuple[NonEmptyText, ...] = ()
    needs_review: bool = False
    decision_certificate: dict[str, Any] = Field(default_factory=dict)
    alert: Alert | None = None
    alert_created: bool = False


class AlertDelivery(DomainContract):
    id: int | None = None
    alert_id: int
    channel: DeliveryChannel = DeliveryChannel.IN_APP
    status: DeliveryStatus = DeliveryStatus.PENDING
    attempt_count: int = Field(default=0, ge=0)
    last_error: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    sent_at: datetime | None = None


class ChannelDeliveryResult(DomainContract):
    succeeded: bool
    error: str | None = None


class DeliveryExecutionResult(DomainContract):
    alert: Alert
    delivery: AlertDelivery
    attempted: bool
