from collections import Counter
from collections.abc import Mapping, Sequence

from threat_alerting.domain import LLMRequest, StructuredLLMResult

FakeOutcome = StructuredLLMResult | Exception


class FakeLLMProvider:
    name = "fake"
    model = "fake-llm-v1"

    def __init__(
        self,
        outcomes: Mapping[str, Sequence[FakeOutcome]] | None = None,
    ) -> None:
        self._outcomes = {name: tuple(values) for name, values in (outcomes or {}).items()}
        if any(not values for values in self._outcomes.values()):
            raise ValueError("configured fake outcome sequences cannot be empty")
        self._call_counts: Counter[str] = Counter()
        self.requests: list[LLMRequest] = []

    def evaluate(self, request: LLMRequest) -> StructuredLLMResult:
        self.requests.append(request)
        call_index = self._call_counts[request.evaluator]
        self._call_counts[request.evaluator] += 1

        configured = self._outcomes.get(request.evaluator)
        if configured:
            outcome = configured[min(call_index, len(configured) - 1)]
        else:
            outcome = _default_result(request.evaluator)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def call_count(self, evaluator: str) -> int:
        return self._call_counts[evaluator]


def _default_result(evaluator: str) -> StructuredLLMResult:
    if evaluator == "impact_expert":
        return StructuredLLMResult(
            score=0.72,
            confidence=0.88,
            reasons=("Potential material organizational impact.",),
            evidence=(),
        )
    if evaluator == "urgency_expert":
        return StructuredLLMResult(
            score=0.68,
            confidence=0.84,
            reasons=("The event warrants timely defensive review.",),
            evidence=(),
        )
    raise ValueError(f"fake provider has no response for evaluator {evaluator!r}")
