from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from threat_alerting.domain import (
    AssessmentStatus,
    ContentMode,
    RawArticle,
)
from threat_alerting.domain.contracts import UnitScore

DEFAULT_CASES_PATH = (
    Path(__file__).resolve().parents[3] / "config" / "fixtures" / "evaluation" / "cases.yaml"
)
DecisionExpectation = Literal["alert", "no_alert", "incomplete"]


class FixtureModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ExpertFixture(FixtureModel):
    score: UnitScore | None = None
    confidence: UnitScore | None = None
    reasons: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    failure: Literal["transient", "permanent"] | None = None

    @model_validator(mode="after")
    def validate_outcome(self) -> "ExpertFixture":
        if self.failure is None:
            if self.score is None or self.confidence is None or not self.reasons:
                raise ValueError(
                    "successful expert fixture requires score, confidence, and reasons"
                )
        elif self.score is not None or self.confidence is not None:
            raise ValueError("failing expert fixture cannot define score or confidence")
        return self


class SourceFixture(FixtureModel):
    name: str = Field(min_length=1)
    content_mode: ContentMode
    trust_score: UnitScore
    articles: tuple[RawArticle, ...] = Field(min_length=1)


class ThresholdFixture(FixtureModel):
    kind: Literal["fixed", "assessment_score"] = "fixed"
    value: UnitScore | None = None

    @model_validator(mode="after")
    def validate_value(self) -> "ThresholdFixture":
        if self.kind == "fixed" and self.value is None:
            raise ValueError("fixed threshold requires a value")
        if self.kind == "assessment_score" and self.value is not None:
            raise ValueError("assessment_score threshold cannot define a value")
        return self


class CaseExpectation(FixtureModel):
    decision: DecisionExpectation
    assessment_status: AssessmentStatus
    needs_review: bool
    reason_codes: tuple[str, ...] = ()
    articles: int = Field(ge=0)
    events: int = Field(ge=0)
    assessments: int = Field(ge=0)
    alerts: int = Field(ge=0)
    duplicates: int = Field(ge=0)
    source_count: int = Field(ge=0)
    provider_calls: dict[str, int] = Field(default_factory=dict)
    prompt_injection_inert: bool = False


class EvaluationCase(FixtureModel):
    id: str = Field(pattern=r"^[a-z0-9_]+$")
    name: str = Field(min_length=1)
    demonstrates: tuple[str, ...] = ()
    threshold: ThresholdFixture
    ingestion_runs: int = Field(default=1, ge=1, le=3)
    sources: tuple[SourceFixture, ...] = Field(min_length=1)
    experts: dict[str, ExpertFixture]
    expected: CaseExpectation

    @model_validator(mode="after")
    def require_complete_expert_panel(self) -> "EvaluationCase":
        if set(self.experts) != {"impact_expert", "urgency_expert"}:
            raise ValueError("cases must define impact_expert and urgency_expert outcomes")
        return self


class EvaluationSuite(FixtureModel):
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    demonstrates: tuple[str, ...] = ()
    cases: tuple[EvaluationCase, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def require_unique_case_ids(self) -> "EvaluationSuite":
        ids = [case.id for case in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("evaluation case IDs must be unique")
        return self


def load_evaluation_suite(path: Path | str = DEFAULT_CASES_PATH) -> EvaluationSuite:
    fixture_path = Path(path)
    payload = yaml.safe_load(fixture_path.read_text(encoding="utf-8"))
    return EvaluationSuite.model_validate(payload)
