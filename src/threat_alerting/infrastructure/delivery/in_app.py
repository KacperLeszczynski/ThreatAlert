from threat_alerting.domain import (
    Alert,
    ChannelDeliveryResult,
    ClientProfile,
    DeliveryChannel,
)


class InAppAlertChannel:
    name = DeliveryChannel.IN_APP

    def deliver(self, alert: Alert, profile: ClientProfile) -> ChannelDeliveryResult:
        return ChannelDeliveryResult(succeeded=True)
