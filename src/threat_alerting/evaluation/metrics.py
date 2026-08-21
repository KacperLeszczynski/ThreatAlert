from dataclasses import dataclass
from typing import Literal

BinaryDecision = Literal["alert", "no_alert"]


@dataclass(frozen=True)
class ClassificationObservation:
    expected: BinaryDecision
    actual: BinaryDecision | Literal["incomplete", "error"]


@dataclass(frozen=True)
class ClassificationMetrics:
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    unclassified: int
    precision: float | None
    recall: float | None


def calculate_classification_metrics(
    observations: tuple[ClassificationObservation, ...],
) -> ClassificationMetrics:
    true_positives = sum(
        item.expected == "alert" and item.actual == "alert" for item in observations
    )
    false_positives = sum(
        item.expected == "no_alert" and item.actual == "alert" for item in observations
    )
    true_negatives = sum(
        item.expected == "no_alert" and item.actual == "no_alert" for item in observations
    )
    false_negatives = sum(
        item.expected == "alert" and item.actual == "no_alert" for item in observations
    )
    unclassified = sum(item.actual in {"incomplete", "error"} for item in observations)
    precision_denominator = true_positives + false_positives
    recall_denominator = true_positives + false_negatives
    return ClassificationMetrics(
        true_positives=true_positives,
        false_positives=false_positives,
        true_negatives=true_negatives,
        false_negatives=false_negatives,
        unclassified=unclassified,
        precision=(true_positives / precision_denominator if precision_denominator else None),
        recall=true_positives / recall_denominator if recall_denominator else None,
    )
