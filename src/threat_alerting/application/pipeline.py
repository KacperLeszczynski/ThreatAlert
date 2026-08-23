import logging
from collections.abc import Callable
from uuid import uuid4

from threat_alerting.application.alerting.decision import AlertDecisionService
from threat_alerting.application.alerting.delivery import AlertDeliveryService
from threat_alerting.application.alerting.profiles import ClientProfileService
from threat_alerting.application.assessment.service import AssessmentService
from threat_alerting.application.ingestion.service import IngestionService
from threat_alerting.domain import (
    AlertDecisionOutcome,
    AssessmentStatus,
    DeliveryStatus,
    PipelineRunSummary,
)
from threat_alerting.domain.ports import AlertChannel

IngestionFactory = Callable[[str | None, str], IngestionService]


class PipelineRunService:
    def __init__(
        self,
        ingestion_factory: IngestionFactory,
        assessment_service: AssessmentService,
        profile_service: ClientProfileService,
        decision_service: AlertDecisionService,
        delivery_service: AlertDeliveryService,
        delivery_channel: AlertChannel,
        *,
        run_id_factory: Callable[[], str] = lambda: str(uuid4()),
        logger: logging.Logger | None = None,
    ) -> None:
        self._ingestion_factory = ingestion_factory
        self._assessment_service = assessment_service
        self._profile_service = profile_service
        self._decision_service = decision_service
        self._delivery_service = delivery_service
        self._delivery_channel = delivery_channel
        self._run_id_factory = run_id_factory
        self._logger = logger or logging.getLogger(__name__)

    def run(self, *, fixture: str | None = None) -> PipelineRunSummary:
        run_id = self._run_id_factory()
        self._log(
            "pipeline_started",
            run_id,
            source_mode="fixture" if fixture else "live",
            fixture_name=fixture,
        )
        ingestion = self._ingestion_factory(fixture, run_id).run()

        complete = 0
        incomplete = 0
        no_alert_decisions = 0
        alerts_created = 0
        alerts_delivered = 0
        alerts_failed = 0
        profiles = self._profile_service.list(enabled_only=True)

        for event_id in ingestion.assessment_candidate_ids:
            assessment = self._assessment_service.assess(event_id)
            if assessment.status is not AssessmentStatus.COMPLETE:
                incomplete += 1
                self._log(
                    "assessment_incomplete",
                    run_id,
                    event_id=event_id,
                    assessment_id=assessment.id,
                )
                continue

            complete += 1
            if assessment.id is None:
                raise RuntimeError("persisted assessment has no id")

            for profile in profiles:
                if profile.id is None:
                    raise RuntimeError("persisted profile has no id")
                decision = self._decision_service.decide(profile.id, assessment.id)
                if decision.outcome is AlertDecisionOutcome.NO_ALERT:
                    no_alert_decisions += 1
                    continue
                if decision.alert is None or decision.alert.id is None:
                    raise RuntimeError("alert decision did not return a persisted alert")
                if decision.alert_created:
                    alerts_created += 1

                delivery = self._delivery_service.deliver(
                    decision.alert.id,
                    self._delivery_channel,
                )
                if delivery.attempted and delivery.delivery.status is DeliveryStatus.SENT:
                    alerts_delivered += 1
                elif delivery.attempted and delivery.delivery.status is DeliveryStatus.FAILED:
                    alerts_failed += 1

        summary = PipelineRunSummary(
            run_id=run_id,
            sources_attempted=ingestion.sources_attempted,
            sources_succeeded=ingestion.sources_succeeded,
            sources_failed=ingestion.sources_failed,
            articles_seen=ingestion.articles_seen,
            articles_new=ingestion.articles_new,
            duplicates_skipped=ingestion.duplicates_skipped,
            malformed_entries=ingestion.malformed_entries,
            events_created=ingestion.events_created,
            events_deferred=ingestion.events_deferred,
            assessments_complete=complete,
            assessments_incomplete=incomplete,
            no_alert_decisions=no_alert_decisions,
            alerts_created=alerts_created,
            alerts_delivered=alerts_delivered,
            alerts_failed=alerts_failed,
            source_failures=ingestion.source_failures,
        )
        summary_fields = summary.model_dump(mode="json")
        summary_fields.pop("run_id")
        self._log("pipeline_completed", run_id, **summary_fields)
        return summary

    def _log(self, event: str, run_id: str, **fields: object) -> None:
        self._logger.info(
            event,
            extra={"event_name": event, "run_id": run_id, **fields},
        )
