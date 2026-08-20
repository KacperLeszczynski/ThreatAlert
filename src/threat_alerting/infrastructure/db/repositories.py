from collections.abc import Callable
from typing import TypeVar

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from threat_alerting.domain import (
    Alert,
    AlertDelivery,
    Assessment,
    ClientProfile,
    NewsArticle,
    RiskResult,
    ThreatEvent,
)
from threat_alerting.domain.enums import DeliveryChannel
from threat_alerting.infrastructure.db.tables import (
    AlertDeliveryRow,
    AlertRow,
    AssessmentRow,
    ClientProfileRow,
    NewsArticleRow,
    ThreatEventArticleRow,
    ThreatEventRow,
)

RowT = TypeVar("RowT")


def _insert_or_find(
    session: Session,
    row: RowT,
    find_existing: Callable[[], RowT | None],
) -> tuple[RowT, bool]:
    try:
        with session.begin_nested():
            session.add(row)
            session.flush()
    except IntegrityError:
        existing = find_existing()
        if existing is None:
            raise
        return existing, False
    return row, True


class NewsArticleRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, article_id: int) -> NewsArticle | None:
        row = self._session.get(NewsArticleRow, article_id)
        return _article_from_row(row) if row else None

    def add_or_get(self, article: NewsArticle) -> tuple[NewsArticle, bool]:
        def find_existing() -> NewsArticleRow | None:
            return self._find_by_identity(article)

        existing = find_existing()
        if existing is not None:
            return _article_from_row(existing), False

        row, created = _insert_or_find(self._session, _article_to_row(article), find_existing)
        return _article_from_row(row), created

    def _find_by_identity(self, article: NewsArticle) -> NewsArticleRow | None:
        if article.external_id is not None:
            row = self._session.scalar(
                select(NewsArticleRow).where(
                    NewsArticleRow.source_name == article.source_name,
                    NewsArticleRow.external_id == article.external_id,
                )
            )
            if row is not None:
                return row
        if article.canonical_url is not None:
            return self._session.scalar(
                select(NewsArticleRow).where(
                    NewsArticleRow.source_name == article.source_name,
                    NewsArticleRow.canonical_url == article.canonical_url,
                )
            )
        return None


class ThreatEventRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, event_id: int) -> ThreatEvent | None:
        row = self._session.get(ThreatEventRow, event_id)
        return _event_from_row(row) if row else None

    def add_or_get(self, event: ThreatEvent) -> tuple[ThreatEvent, bool]:
        def find_existing() -> ThreatEventRow | None:
            return self._session.scalar(
                select(ThreatEventRow).where(ThreatEventRow.event_key == event.event_key)
            )

        existing = find_existing()
        if existing is not None:
            return _event_from_row(existing), False

        row, created = _insert_or_find(self._session, _event_to_row(event), find_existing)
        return _event_from_row(row), created

    def link_article(self, event_id: int, article_id: int) -> bool:
        query = select(ThreatEventArticleRow).where(
            ThreatEventArticleRow.event_id == event_id,
            ThreatEventArticleRow.article_id == article_id,
        )
        if self._session.scalar(query) is not None:
            return False

        row = ThreatEventArticleRow(event_id=event_id, article_id=article_id)
        _, created = _insert_or_find(self._session, row, lambda: self._session.scalar(query))
        return created


class AssessmentRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, assessment_id: int) -> Assessment | None:
        row = self._session.get(AssessmentRow, assessment_id)
        return _assessment_from_row(row) if row else None

    def add_or_get(self, assessment: Assessment) -> tuple[Assessment, bool]:
        def find_existing() -> AssessmentRow | None:
            return self._session.scalar(
                select(AssessmentRow).where(
                    AssessmentRow.event_id == assessment.event_id,
                    AssessmentRow.assessment_version == assessment.assessment_version,
                )
            )

        existing = find_existing()
        if existing is not None:
            return _assessment_from_row(existing), False

        row, created = _insert_or_find(self._session, _assessment_to_row(assessment), find_existing)
        return _assessment_from_row(row), created


class ClientProfileRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, profile_id: int) -> ClientProfile | None:
        row = self._session.get(ClientProfileRow, profile_id)
        return _profile_from_row(row) if row else None

    def add(self, profile: ClientProfile) -> ClientProfile:
        row = _profile_to_row(profile)
        self._session.add(row)
        self._session.flush()
        return _profile_from_row(row)

    def list_enabled(self) -> list[ClientProfile]:
        rows = self._session.scalars(
            select(ClientProfileRow)
            .where(ClientProfileRow.enabled.is_(True))
            .order_by(ClientProfileRow.id)
        )
        return [_profile_from_row(row) for row in rows]


class AlertRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, alert_id: int) -> Alert | None:
        row = self._session.get(AlertRow, alert_id)
        return _alert_from_row(row) if row else None

    def add_or_get(self, alert: Alert) -> tuple[Alert, bool]:
        def find_existing() -> AlertRow | None:
            return self._session.scalar(
                select(AlertRow).where(
                    AlertRow.profile_id == alert.profile_id,
                    AlertRow.assessment_id == alert.assessment_id,
                )
            )

        existing = find_existing()
        if existing is not None:
            return _alert_from_row(existing), False

        row, created = _insert_or_find(self._session, _alert_to_row(alert), find_existing)
        return _alert_from_row(row), created


class AlertDeliveryRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, delivery_id: int) -> AlertDelivery | None:
        row = self._session.get(AlertDeliveryRow, delivery_id)
        return _delivery_from_row(row) if row else None

    def add_or_get(self, delivery: AlertDelivery) -> tuple[AlertDelivery, bool]:
        def find_existing() -> AlertDeliveryRow | None:
            return self._session.scalar(
                select(AlertDeliveryRow).where(
                    AlertDeliveryRow.alert_id == delivery.alert_id,
                    AlertDeliveryRow.channel == delivery.channel,
                )
            )

        existing = find_existing()
        if existing is not None:
            return _delivery_from_row(existing), False

        row, created = _insert_or_find(self._session, _delivery_to_row(delivery), find_existing)
        return _delivery_from_row(row), created

    def get_for_alert(self, alert_id: int, channel: DeliveryChannel) -> AlertDelivery | None:
        row = self._session.scalar(
            select(AlertDeliveryRow).where(
                AlertDeliveryRow.alert_id == alert_id,
                AlertDeliveryRow.channel == channel,
            )
        )
        return _delivery_from_row(row) if row else None


def _article_to_row(article: NewsArticle) -> NewsArticleRow:
    return NewsArticleRow(
        source_name=article.source_name,
        external_id=article.external_id,
        canonical_url=article.canonical_url,
        title=article.title,
        content=article.content,
        content_mode=article.content_mode,
        content_quality=article.content_quality,
        published_at=article.published_at,
        fetched_at=article.fetched_at,
        content_hash=article.content_hash,
        raw_metadata=article.raw_metadata,
    )


def _article_from_row(row: NewsArticleRow) -> NewsArticle:
    return NewsArticle(
        id=row.id,
        source_name=row.source_name,
        external_id=row.external_id,
        canonical_url=row.canonical_url,
        title=row.title,
        content=row.content,
        content_mode=row.content_mode,
        content_quality=row.content_quality,
        published_at=row.published_at,
        fetched_at=row.fetched_at,
        content_hash=row.content_hash,
        raw_metadata=row.raw_metadata,
    )


def _event_to_row(event: ThreatEvent) -> ThreatEventRow:
    return ThreatEventRow(
        event_key=event.event_key,
        event_type=event.event_type,
        cve_id=event.cve_id,
        vendors=list(event.vendors),
        products=list(event.products),
        categories=list(event.categories),
        first_seen_at=event.first_seen_at,
        last_seen_at=event.last_seen_at,
        corroborating_source_count=event.corroborating_source_count,
    )


def _event_from_row(row: ThreatEventRow) -> ThreatEvent:
    return ThreatEvent(
        id=row.id,
        event_key=row.event_key,
        event_type=row.event_type,
        cve_id=row.cve_id,
        vendors=tuple(row.vendors),
        products=tuple(row.products),
        categories=tuple(row.categories),
        first_seen_at=row.first_seen_at,
        last_seen_at=row.last_seen_at,
        corroborating_source_count=row.corroborating_source_count,
    )


def _assessment_to_row(assessment: Assessment) -> AssessmentRow:
    return AssessmentRow(
        event_id=assessment.event_id,
        assessment_version=assessment.assessment_version,
        status=assessment.status,
        evaluator_results=[
            result.model_dump(mode="json") for result in assessment.evaluator_results
        ],
        average_score=assessment.average_score,
        score_disagreement=assessment.score_disagreement,
        content_quality=assessment.content_quality,
        model_metadata=assessment.model_metadata,
        prompt_versions=assessment.prompt_versions,
        failure_reasons=list(assessment.failure_reasons),
        created_at=assessment.created_at,
    )


def _assessment_from_row(row: AssessmentRow) -> Assessment:
    return Assessment(
        id=row.id,
        event_id=row.event_id,
        assessment_version=row.assessment_version,
        status=row.status,
        evaluator_results=tuple(
            RiskResult.model_validate(result) for result in row.evaluator_results
        ),
        average_score=row.average_score,
        score_disagreement=row.score_disagreement,
        content_quality=row.content_quality,
        model_metadata=row.model_metadata,
        prompt_versions=row.prompt_versions,
        failure_reasons=tuple(row.failure_reasons),
        created_at=row.created_at,
    )


def _profile_to_row(profile: ClientProfile) -> ClientProfileRow:
    return ClientProfileRow(
        name=profile.name,
        minimum_score=profile.minimum_score,
        vendors=list(profile.vendors),
        products=list(profile.products),
        categories=list(profile.categories),
        enabled=profile.enabled,
        created_at=profile.created_at,
        updated_at=profile.updated_at,
    )


def _profile_from_row(row: ClientProfileRow) -> ClientProfile:
    return ClientProfile(
        id=row.id,
        name=row.name,
        minimum_score=row.minimum_score,
        vendors=tuple(row.vendors),
        products=tuple(row.products),
        categories=tuple(row.categories),
        enabled=row.enabled,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _alert_to_row(alert: Alert) -> AlertRow:
    return AlertRow(
        profile_id=alert.profile_id,
        assessment_id=alert.assessment_id,
        event_id=alert.event_id,
        title=alert.title,
        summary=alert.summary,
        average_score=alert.average_score,
        threshold=alert.threshold,
        decision_margin=alert.decision_margin,
        needs_review=alert.needs_review,
        decision_certificate=alert.decision_certificate,
        status=alert.status,
        created_at=alert.created_at,
        updated_at=alert.updated_at,
    )


def _alert_from_row(row: AlertRow) -> Alert:
    return Alert(
        id=row.id,
        profile_id=row.profile_id,
        assessment_id=row.assessment_id,
        event_id=row.event_id,
        title=row.title,
        summary=row.summary,
        average_score=row.average_score,
        threshold=row.threshold,
        decision_margin=row.decision_margin,
        needs_review=row.needs_review,
        decision_certificate=row.decision_certificate,
        status=row.status,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _delivery_to_row(delivery: AlertDelivery) -> AlertDeliveryRow:
    return AlertDeliveryRow(
        alert_id=delivery.alert_id,
        channel=delivery.channel,
        status=delivery.status,
        attempt_count=delivery.attempt_count,
        last_error=delivery.last_error,
        created_at=delivery.created_at,
        sent_at=delivery.sent_at,
    )


def _delivery_from_row(row: AlertDeliveryRow) -> AlertDelivery:
    return AlertDelivery(
        id=row.id,
        alert_id=row.alert_id,
        channel=row.channel,
        status=row.status,
        attempt_count=row.attempt_count,
        last_error=row.last_error,
        created_at=row.created_at,
        sent_at=row.sent_at,
    )
