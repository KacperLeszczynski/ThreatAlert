from collections.abc import Callable
from datetime import UTC, datetime

from threat_alerting.domain import (
    AlertDelivery,
    AlertStatus,
    DeliveryExecutionResult,
    DeliveryStatus,
)
from threat_alerting.domain.ports import AlertChannel, AlertUnitOfWork


class AlertDeliveryService:
    def __init__(
        self,
        unit_of_work_factory: Callable[[], AlertUnitOfWork],
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._unit_of_work_factory = unit_of_work_factory
        self._clock = clock

    def deliver(self, alert_id: int, channel: AlertChannel) -> DeliveryExecutionResult:
        with self._unit_of_work_factory() as unit_of_work:
            alert = unit_of_work.alerts.get(alert_id)
            if alert is None:
                raise LookupError(f"alert {alert_id} does not exist")
            profile = unit_of_work.client_profiles.get(alert.profile_id)
            if profile is None:
                raise LookupError(f"client profile {alert.profile_id} does not exist")
            delivery = unit_of_work.alert_deliveries.get_for_alert(alert_id, channel.name)
            if delivery is not None and delivery.status is DeliveryStatus.SENT:
                return DeliveryExecutionResult(alert=alert, delivery=delivery, attempted=False)

            if delivery is None:
                delivery, _ = unit_of_work.alert_deliveries.add_or_get(
                    AlertDelivery(
                        alert_id=alert_id,
                        channel=channel.name,
                        status=DeliveryStatus.PENDING,
                        created_at=self._clock(),
                    )
                )
            elif delivery.status is DeliveryStatus.FAILED:
                delivery = unit_of_work.alert_deliveries.update(
                    delivery.model_copy(
                        update={
                            "status": DeliveryStatus.PENDING,
                            "last_error": None,
                            "sent_at": None,
                        }
                    )
                )
                alert = unit_of_work.alerts.update(
                    alert.model_copy(
                        update={"status": AlertStatus.PENDING, "updated_at": self._clock()}
                    )
                )
            unit_of_work.commit()

        try:
            channel_result = channel.deliver(alert, profile)
            succeeded = channel_result.succeeded
            error = channel_result.error
        except Exception as exc:
            succeeded = False
            error = f"{type(exc).__name__}: {exc}"
        if not succeeded and not error:
            error = "channel reported an unsuccessful delivery"

        now = self._clock()
        with self._unit_of_work_factory() as unit_of_work:
            current_alert = unit_of_work.alerts.get(alert_id)
            current_delivery = unit_of_work.alert_deliveries.get_for_alert(
                alert_id,
                channel.name,
            )
            if current_alert is None or current_delivery is None:
                raise RuntimeError("persisted delivery state disappeared during delivery")

            updated_delivery = unit_of_work.alert_deliveries.update(
                current_delivery.model_copy(
                    update={
                        "status": (DeliveryStatus.SENT if succeeded else DeliveryStatus.FAILED),
                        "attempt_count": current_delivery.attempt_count + 1,
                        "last_error": None if succeeded else error[:1000],
                        "sent_at": now if succeeded else None,
                    }
                )
            )
            updated_alert = unit_of_work.alerts.update(
                current_alert.model_copy(
                    update={
                        "status": AlertStatus.SENT if succeeded else AlertStatus.FAILED,
                        "updated_at": now,
                    }
                )
            )
            unit_of_work.commit()

        return DeliveryExecutionResult(
            alert=updated_alert,
            delivery=updated_delivery,
            attempted=True,
        )
