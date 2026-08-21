import operator
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Annotated, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from threat_alerting.application.assessment.aggregation import (
    ArithmeticMeanAggregator,
    IncompleteEvaluatorPanelError,
)
from threat_alerting.domain import AggregateResult, EvaluationContext, RiskResult
from threat_alerting.domain.ports import RiskEvaluator


class _AssessmentState(TypedDict, total=False):
    context: EvaluationContext
    evaluator_results: Annotated[list[RiskResult], operator.add]
    failure_reasons: Annotated[list[str], operator.add]
    aggregate_result: AggregateResult | None


@dataclass(frozen=True)
class AssessmentGraphResult:
    evaluator_results: tuple[RiskResult, ...]
    aggregate_result: AggregateResult | None
    failure_reasons: tuple[str, ...]


class RiskAssessmentGraph:
    def __init__(
        self,
        evaluators: Sequence[RiskEvaluator],
        aggregator: ArithmeticMeanAggregator | None = None,
    ) -> None:
        self._aggregator = aggregator or ArithmeticMeanAggregator()
        by_name = {evaluator.name: evaluator for evaluator in evaluators}
        if len(by_name) != len(evaluators):
            raise ValueError("evaluator names must be unique")
        if set(by_name) != set(self._aggregator.required_evaluators):
            raise ValueError("graph evaluators must exactly match the required evaluator panel")
        self._graph = self._build_graph(by_name)

    def run(self, context: EvaluationContext) -> AssessmentGraphResult:
        state = self._graph.invoke(
            {
                "context": context,
                "evaluator_results": [],
                "failure_reasons": [],
                "aggregate_result": None,
            }
        )
        return AssessmentGraphResult(
            evaluator_results=tuple(state.get("evaluator_results", ())),
            aggregate_result=state.get("aggregate_result"),
            failure_reasons=tuple(state.get("failure_reasons", ())),
        )

    @property
    def compiled_graph(self) -> CompiledStateGraph:
        return self._graph

    def _build_graph(self, evaluators: dict[str, RiskEvaluator]):
        builder = StateGraph(_AssessmentState)
        node_names = []
        for evaluator_name, evaluator in evaluators.items():
            node_name = f"evaluate_{evaluator_name}"
            node_names.append(node_name)
            builder.add_node(node_name, self._evaluator_node(evaluator))
            builder.add_edge(START, node_name)

        builder.add_node("aggregate", self._aggregate_node)
        builder.add_edge(node_names, "aggregate")
        builder.add_edge("aggregate", END)
        return builder.compile()

    @staticmethod
    def _evaluator_node(evaluator: RiskEvaluator):
        def evaluate(state: _AssessmentState) -> _AssessmentState:
            try:
                context = EvaluationContext.model_validate(state["context"])
                return {"evaluator_results": [evaluator.evaluate(context)]}
            except Exception as exc:
                return {"failure_reasons": [f"{evaluator.name}: {type(exc).__name__}: {exc}"]}

        return evaluate

    def _aggregate_node(self, state: _AssessmentState) -> _AssessmentState:
        if state.get("failure_reasons"):
            return {"aggregate_result": None}
        try:
            aggregate = self._aggregator.aggregate(state.get("evaluator_results", []))
        except IncompleteEvaluatorPanelError as exc:
            return {
                "aggregate_result": None,
                "failure_reasons": [str(exc)],
            }
        return {"aggregate_result": aggregate}
