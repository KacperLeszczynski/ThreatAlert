from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy import Enum as SqlEnum
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from threat_alerting.domain.enums import (
    AlertStatus,
    AssessmentStatus,
    ContentMode,
    ContentQuality,
    DeliveryChannel,
    DeliveryStatus,
    EventType,
)
from threat_alerting.domain.models import utc_now

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def enum_column(enum_type: type, name: str) -> SqlEnum:
    return SqlEnum(
        enum_type,
        values_callable=lambda members: [member.value for member in members],
        native_enum=False,
        validate_strings=True,
        create_constraint=True,
        name=name,
    )


class NewsArticleRow(Base):
    __tablename__ = "news_articles"
    __table_args__ = (
        UniqueConstraint("source_name", "external_id", name="uq_news_source_external_id"),
        UniqueConstraint("source_name", "canonical_url", name="uq_news_source_canonical_url"),
        CheckConstraint(
            "external_id IS NOT NULL OR canonical_url IS NOT NULL",
            name="source_identity_required",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_name: Mapped[str] = mapped_column(String(100), nullable=False)
    external_id: Mapped[str | None] = mapped_column(String(500))
    canonical_url: Mapped[str | None] = mapped_column(String(2048))
    title: Mapped[str] = mapped_column(String(1000), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    content_mode: Mapped[ContentMode] = mapped_column(
        enum_column(ContentMode, "news_content_mode"), nullable=False
    )
    content_quality: Mapped[ContentQuality] = mapped_column(
        enum_column(ContentQuality, "news_content_quality"), nullable=False
    )
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    event_links: Mapped[list[ThreatEventArticleRow]] = relationship(
        back_populates="article", cascade="all, delete-orphan"
    )


class ThreatEventRow(Base):
    __tablename__ = "threat_events"
    __table_args__ = (
        UniqueConstraint("event_key", name="uq_threat_events_event_key"),
        CheckConstraint(
            "corroborating_source_count >= 0", name="nonnegative_corroborating_sources"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_key: Mapped[str] = mapped_column(String(255), nullable=False)
    event_type: Mapped[EventType] = mapped_column(
        enum_column(EventType, "threat_event_type"), nullable=False
    )
    cve_id: Mapped[str | None] = mapped_column(String(32))
    vendors: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    products: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    categories: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    corroborating_source_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    article_links: Mapped[list[ThreatEventArticleRow]] = relationship(
        back_populates="event", cascade="all, delete-orphan"
    )
    assessments: Mapped[list[AssessmentRow]] = relationship(
        back_populates="event", cascade="all, delete-orphan"
    )
    alerts: Mapped[list[AlertRow]] = relationship(back_populates="event")


class ThreatEventArticleRow(Base):
    __tablename__ = "threat_event_articles"
    __table_args__ = (UniqueConstraint("event_id", "article_id", name="uq_event_article_link"),)

    event_id: Mapped[int] = mapped_column(
        ForeignKey("threat_events.id", ondelete="CASCADE"), primary_key=True
    )
    article_id: Mapped[int] = mapped_column(
        ForeignKey("news_articles.id", ondelete="CASCADE"), primary_key=True
    )

    event: Mapped[ThreatEventRow] = relationship(back_populates="article_links")
    article: Mapped[NewsArticleRow] = relationship(back_populates="event_links")


class AssessmentRow(Base):
    __tablename__ = "assessments"
    __table_args__ = (
        UniqueConstraint("event_id", "assessment_version", name="uq_assessment_event_version"),
        CheckConstraint(
            "average_score IS NULL OR (average_score >= 0 AND average_score <= 1)",
            name="average_score_unit_interval",
        ),
        CheckConstraint(
            "score_disagreement IS NULL OR (score_disagreement >= 0 AND score_disagreement <= 1)",
            name="score_disagreement_unit_interval",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[int] = mapped_column(
        ForeignKey("threat_events.id", ondelete="CASCADE"), nullable=False
    )
    assessment_version: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[AssessmentStatus] = mapped_column(
        enum_column(AssessmentStatus, "assessment_status"), nullable=False
    )
    evaluator_results: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list, nullable=False
    )
    average_score: Mapped[float | None] = mapped_column(Float)
    score_disagreement: Mapped[float | None] = mapped_column(Float)
    content_quality: Mapped[ContentQuality] = mapped_column(
        enum_column(ContentQuality, "assessment_content_quality"), nullable=False
    )
    model_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    prompt_versions: Mapped[dict[str, str]] = mapped_column(JSON, default=dict, nullable=False)
    failure_reasons: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    event: Mapped[ThreatEventRow] = relationship(back_populates="assessments")
    alerts: Mapped[list[AlertRow]] = relationship(back_populates="assessment")


class ClientProfileRow(Base):
    __tablename__ = "client_profiles"
    __table_args__ = (
        CheckConstraint(
            "minimum_score >= 0 AND minimum_score <= 1", name="minimum_score_unit_interval"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    minimum_score: Mapped[float] = mapped_column(Float, nullable=False)
    vendors: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    products: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    categories: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    alerts: Mapped[list[AlertRow]] = relationship(back_populates="profile")


class AlertRow(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        UniqueConstraint("profile_id", "assessment_id", name="uq_alert_profile_assessment"),
        CheckConstraint(
            "average_score >= 0 AND average_score <= 1", name="average_score_unit_interval"
        ),
        CheckConstraint("threshold >= 0 AND threshold <= 1", name="threshold_unit_interval"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    profile_id: Mapped[int] = mapped_column(
        ForeignKey("client_profiles.id", ondelete="CASCADE"), nullable=False
    )
    assessment_id: Mapped[int] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    event_id: Mapped[int] = mapped_column(
        ForeignKey("threat_events.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(1000), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    average_score: Mapped[float] = mapped_column(Float, nullable=False)
    threshold: Mapped[float] = mapped_column(Float, nullable=False)
    decision_margin: Mapped[float] = mapped_column(Float, nullable=False)
    needs_review: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    decision_certificate: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[AlertStatus] = mapped_column(
        enum_column(AlertStatus, "alert_status"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    profile: Mapped[ClientProfileRow] = relationship(back_populates="alerts")
    assessment: Mapped[AssessmentRow] = relationship(back_populates="alerts")
    event: Mapped[ThreatEventRow] = relationship(back_populates="alerts")
    deliveries: Mapped[list[AlertDeliveryRow]] = relationship(
        back_populates="alert", cascade="all, delete-orphan"
    )


class AlertDeliveryRow(Base):
    __tablename__ = "alert_deliveries"
    __table_args__ = (
        UniqueConstraint("alert_id", "channel", name="uq_delivery_alert_channel"),
        CheckConstraint("attempt_count >= 0", name="nonnegative_attempt_count"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False
    )
    channel: Mapped[DeliveryChannel] = mapped_column(
        enum_column(DeliveryChannel, "delivery_channel"), nullable=False
    )
    status: Mapped[DeliveryStatus] = mapped_column(
        enum_column(DeliveryStatus, "delivery_status"), nullable=False
    )
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    alert: Mapped[AlertRow] = relationship(back_populates="deliveries")
