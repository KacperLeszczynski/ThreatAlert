from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

NonEmptyText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
UnitScore = Annotated[float, Field(ge=0.0, le=1.0)]


class DomainContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class EvidenceItem(DomainContract):
    quote: NonEmptyText
    verified: bool = False


class LLMEvidenceQuote(DomainContract):
    quote: NonEmptyText


class StructuredLLMResult(DomainContract):
    score: UnitScore
    confidence: UnitScore
    reasons: tuple[NonEmptyText, ...]
    evidence: tuple[LLMEvidenceQuote, ...]


class RiskResult(DomainContract):
    evaluator: NonEmptyText
    score: UnitScore
    confidence: UnitScore
    reasons: tuple[NonEmptyText, ...] = ()
    evidence: tuple[EvidenceItem, ...] = ()
    provider: NonEmptyText | None = None
    model: NonEmptyText | None = None
    prompt_version: NonEmptyText | None = None
    duration_ms: int = Field(default=0, ge=0)
    attempt_count: int = Field(default=1, ge=1)


class AggregateResult(DomainContract):
    results: tuple[RiskResult, ...] = Field(min_length=1)
    average_score: UnitScore
    score_disagreement: UnitScore
