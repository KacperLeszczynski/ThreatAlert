from collections.abc import Callable, Mapping

from threat_alerting.application.assessment_graph import RiskAssessmentGraph
from threat_alerting.domain import (
    Assessment,
    AssessmentStatus,
    ContentQuality,
    EvaluationContext,
)
from threat_alerting.domain.ports import AssessmentUnitOfWork


class AssessmentService:
    def __init__(
        self,
        unit_of_work_factory: Callable[[], AssessmentUnitOfWork],
        graph: RiskAssessmentGraph,
        *,
        assessment_version: str = "v1",
        source_trust_scores: Mapping[str, float] | None = None,
    ) -> None:
        self._unit_of_work_factory = unit_of_work_factory
        self._graph = graph
        self._assessment_version = assessment_version
        self._source_trust_scores = dict(source_trust_scores or {})

    def assess(self, event_id: int) -> Assessment:
        with self._unit_of_work_factory() as unit_of_work:
            existing = unit_of_work.assessments.get_by_event_version(
                event_id,
                self._assessment_version,
            )
            if existing is not None:
                return existing
            event = unit_of_work.threat_events.get(event_id)
            if event is None:
                raise LookupError(f"threat event {event_id} does not exist")
            articles = tuple(unit_of_work.news_articles.list_for_event(event_id))

        if not articles:
            raise ValueError(f"threat event {event_id} has no linked articles")

        context = EvaluationContext(
            event=event,
            articles=articles,
            source_trust_scores=self._source_trust_scores,
        )
        quality = (
            ContentQuality.FULL
            if any(article.content_quality is ContentQuality.FULL for article in articles)
            else ContentQuality.LIMITED
        )
        outcome = self._graph.run(context)
        complete = outcome.aggregate_result is not None and not outcome.failure_reasons
        results = (
            outcome.aggregate_result.results
            if outcome.aggregate_result is not None
            else outcome.evaluator_results
        )
        assessment = Assessment(
            event_id=event_id,
            assessment_version=self._assessment_version,
            status=(AssessmentStatus.COMPLETE if complete else AssessmentStatus.INCOMPLETE),
            evaluator_results=results,
            average_score=(
                outcome.aggregate_result.average_score if outcome.aggregate_result else None
            ),
            score_disagreement=(
                outcome.aggregate_result.score_disagreement if outcome.aggregate_result else None
            ),
            content_quality=quality,
            model_metadata={
                "limited_context": quality is ContentQuality.LIMITED,
                "evaluators": {
                    result.evaluator: {
                        "provider": result.provider,
                        "model": result.model,
                        "attempt_count": result.attempt_count,
                    }
                    for result in results
                },
            },
            prompt_versions={
                result.evaluator: result.prompt_version
                for result in results
                if result.prompt_version is not None
            },
            failure_reasons=outcome.failure_reasons,
        )

        with self._unit_of_work_factory() as unit_of_work:
            stored, _ = unit_of_work.assessments.add_or_get(assessment)
            unit_of_work.commit()
        return stored
