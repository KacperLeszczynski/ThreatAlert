from types import TracebackType

from sqlalchemy.orm import Session

from threat_alerting.infrastructure.db.repositories import (
    AlertDeliveryRepository,
    AlertRepository,
    AssessmentRepository,
    ClientProfileRepository,
    NewsArticleRepository,
    ThreatEventRepository,
)
from threat_alerting.infrastructure.db.session import SessionFactory


class SqlAlchemyUnitOfWork:
    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory
        self._session: Session | None = None
        self._committed = False

    def __enter__(self) -> "SqlAlchemyUnitOfWork":
        if self._session is not None:
            raise RuntimeError("unit of work is already active")

        self._session = self._session_factory()
        self._committed = False
        self.news_articles = NewsArticleRepository(self._session)
        self.threat_events = ThreatEventRepository(self._session)
        self.assessments = AssessmentRepository(self._session)
        self.client_profiles = ClientProfileRepository(self._session)
        self.alerts = AlertRepository(self._session)
        self.alert_deliveries = AlertDeliveryRepository(self._session)
        return self

    def commit(self) -> None:
        self._require_session().commit()
        self._committed = True

    def rollback(self) -> None:
        self._require_session().rollback()
        self._committed = False

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        session = self._require_session()
        try:
            if exc_type is not None or not self._committed:
                session.rollback()
        finally:
            session.close()
            self._session = None
            self._committed = False

    def _require_session(self) -> Session:
        if self._session is None:
            raise RuntimeError("unit of work must be used as a context manager")
        return self._session
