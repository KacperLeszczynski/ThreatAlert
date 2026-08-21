from decimal import Decimal

from threat_alerting.domain import AggregateResult, RiskResult


class IncompleteEvaluatorPanelError(ValueError):
    pass


class ArithmeticMeanAggregator:
    def __init__(
        self,
        required_evaluators: tuple[str, ...] = (
            "deterministic",
            "impact_expert",
            "urgency_expert",
        ),
    ) -> None:
        if len(set(required_evaluators)) != len(required_evaluators):
            raise ValueError("required evaluator names must be unique")
        self.required_evaluators = required_evaluators

    def aggregate(self, results: list[RiskResult]) -> AggregateResult:
        by_name = {result.evaluator: result for result in results}
        if len(by_name) != len(results):
            raise IncompleteEvaluatorPanelError("evaluator results contain duplicate names")

        required = set(self.required_evaluators)
        actual = set(by_name)
        if actual != required:
            missing = sorted(required - actual)
            unexpected = sorted(actual - required)
            details = []
            if missing:
                details.append(f"missing={','.join(missing)}")
            if unexpected:
                details.append(f"unexpected={','.join(unexpected)}")
            raise IncompleteEvaluatorPanelError("incomplete evaluator panel: " + "; ".join(details))

        ordered = tuple(by_name[name] for name in self.required_evaluators)
        scores = [Decimal(str(result.score)) for result in ordered]
        average = sum(scores, start=Decimal(0)) / Decimal(len(scores))
        disagreement = max(scores) - min(scores)
        return AggregateResult(
            results=ordered,
            average_score=float(average),
            score_disagreement=float(disagreement),
        )
