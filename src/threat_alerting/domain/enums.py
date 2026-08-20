from enum import StrEnum


class AssessmentStatus(StrEnum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    FAILED = "failed"


class AlertStatus(StrEnum):
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"


class DeliveryStatus(StrEnum):
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"


class DeliveryChannel(StrEnum):
    IN_APP = "in_app"


class EventType(StrEnum):
    VULNERABILITY = "vulnerability"
    INCIDENT = "incident"
    CAMPAIGN = "campaign"
    UNKNOWN = "unknown"


class ContentMode(StrEnum):
    FULL_RSS = "full_rss"
    SUMMARY_ONLY = "summary_only"


class ContentQuality(StrEnum):
    FULL = "full"
    LIMITED = "limited"
