from types import SimpleNamespace

from threat_alerting.application.pipeline import PipelineRunService
from threat_alerting.domain import AssessmentStatus, IngestionSummary


class StubIngestionService:
    def __init__(self, summary: IngestionSummary) -> None:
        self._summary = summary

    def run(self) -> IngestionSummary:
        return self._summary


class RecordingAssessmentService:
    def __init__(self) -> None:
        self.event_ids: list[int] = []

    def assess(self, event_id: int):
        self.event_ids.append(event_id)
        return SimpleNamespace(status=AssessmentStatus.COMPLETE, id=event_id)


class EmptyProfileService:
    def list(self, *, enabled_only: bool):
        assert enabled_only is True
        return ()


def test_pipeline_assesses_only_immediate_candidates() -> None:
    candidate_ids = tuple(range(1, 11))
    ingestion = IngestionSummary(
        run_id="ingestion-run",
        events_created=12,
        events_deferred=2,
        created_event_ids=tuple(range(1, 13)),
        assessment_candidate_ids=candidate_ids,
        deferred_event_ids=(11, 12),
    )
    assessments = RecordingAssessmentService()
    pipeline = PipelineRunService(
        lambda _fixture, _run_id: StubIngestionService(ingestion),
        assessments,
        EmptyProfileService(),
        SimpleNamespace(),
        SimpleNamespace(),
        SimpleNamespace(),
        run_id_factory=lambda: "pipeline-run",
    )

    summary = pipeline.run()

    assert assessments.event_ids == list(candidate_ids)
    assert summary.events_created == 12
    assert summary.events_deferred == 2
    assert summary.assessments_complete == 10
