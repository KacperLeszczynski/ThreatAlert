from collections.abc import Callable
from typing import Any

from threat_alerting.domain import Alert, Assessment, NewsArticle
from threat_alerting.domain.ports import AlertUnitOfWork


class ReadService:
    def __init__(self, unit_of_work_factory: Callable[[], AlertUnitOfWork]) -> None:
        self._unit_of_work_factory = unit_of_work_factory

    def list_articles(self, *, limit: int, offset: int) -> tuple[NewsArticle, ...]:
        with self._unit_of_work_factory() as unit_of_work:
            return tuple(unit_of_work.news_articles.list(limit=limit, offset=offset))

    def list_assessments(self, *, limit: int, offset: int) -> tuple[Assessment, ...]:
        with self._unit_of_work_factory() as unit_of_work:
            return tuple(unit_of_work.assessments.list(limit=limit, offset=offset))

    def list_alerts(
        self,
        *,
        limit: int,
        offset: int,
        profile_id: int | None = None,
    ) -> tuple[Alert, ...]:
        with self._unit_of_work_factory() as unit_of_work:
            if profile_id is not None and unit_of_work.client_profiles.get(profile_id) is None:
                raise LookupError(f"client profile {profile_id} does not exist")
            return tuple(
                unit_of_work.alerts.list(
                    limit=limit,
                    offset=offset,
                    profile_id=profile_id,
                )
            )

    def get_alert(self, alert_id: int) -> Alert:
        with self._unit_of_work_factory() as unit_of_work:
            alert = unit_of_work.alerts.get(alert_id)
        if alert is None:
            raise LookupError(f"alert {alert_id} does not exist")
        return alert

    def get_decision_certificate(self, alert_id: int) -> dict[str, Any]:
        alert = self.get_alert(alert_id)
        return {"alert_id": alert_id, **alert.decision_certificate}
