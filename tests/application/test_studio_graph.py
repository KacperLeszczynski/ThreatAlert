import json
from pathlib import Path

from threat_alerting.domain import AggregateResult
from threat_alerting.settings import Settings
from threat_alerting.studio import build_studio_graph

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FAKE_SETTINGS = Settings(_env_file=None, llm_provider="fake", llm_api_key=None)


def test_studio_graph_uses_the_existing_assessment_topology() -> None:
    graph = build_studio_graph(FAKE_SETTINGS)

    assert set(graph.get_graph().nodes) == {
        "__start__",
        "evaluate_deterministic",
        "evaluate_impact_expert",
        "evaluate_urgency_expert",
        "aggregate",
        "__end__",
    }


def test_studio_graph_accepts_the_documented_json_input() -> None:
    input_path = PROJECT_ROOT / "config" / "studio" / "risk_assessment_input.json"
    state = json.loads(input_path.read_text(encoding="utf-8"))

    output = build_studio_graph(FAKE_SETTINGS).invoke(state)

    aggregate = AggregateResult.model_validate(output["aggregate_result"])
    assert {result.evaluator for result in aggregate.results} == {
        "deterministic",
        "impact_expert",
        "urgency_expert",
    }
    assert output["failure_reasons"] == []
