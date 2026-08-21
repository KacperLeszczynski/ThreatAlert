from langgraph.graph.state import CompiledStateGraph

from threat_alerting.application import (
    DeterministicRiskEvaluator,
    ImpactExpert,
    RiskAssessmentGraph,
    UrgencyExpert,
)
from threat_alerting.infrastructure.llm import create_llm_provider
from threat_alerting.settings import Settings


def build_studio_graph(settings: Settings | None = None) -> CompiledStateGraph:
    resolved_settings = settings or Settings()
    provider = create_llm_provider(resolved_settings)

    return RiskAssessmentGraph(
        (
            DeterministicRiskEvaluator(),
            ImpactExpert(
                provider,
                max_attempts=resolved_settings.llm_max_attempts,
                schema_max_attempts=resolved_settings.llm_schema_max_attempts,
                article_max_characters=resolved_settings.article_max_characters,
                summary_confidence_multiplier=resolved_settings.summary_confidence_multiplier,
            ),
            UrgencyExpert(
                provider,
                max_attempts=resolved_settings.llm_max_attempts,
                schema_max_attempts=resolved_settings.llm_schema_max_attempts,
                article_max_characters=resolved_settings.article_max_characters,
                summary_confidence_multiplier=resolved_settings.summary_confidence_multiplier,
            ),
        )
    ).compiled_graph


graph = build_studio_graph()
