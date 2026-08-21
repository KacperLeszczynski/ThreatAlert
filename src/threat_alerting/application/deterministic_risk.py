import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from time import perf_counter

from threat_alerting.domain import ContentQuality, EvaluationContext, EvidenceItem, RiskResult
from threat_alerting.domain.signals import EXPLOITATION_NEGATIONS, mask_exploitation_negations


@dataclass(frozen=True)
class DeterministicScoringConfig:
    exploitation_weight: float = 0.35
    impact_weight: float = 0.25
    exposure_weight: float = 0.15
    credibility_weight: float = 0.15
    freshness_weight: float = 0.10
    neutral_source_trust: float = 0.50
    summary_confidence_multiplier: float = 0.75

    def __post_init__(self) -> None:
        weights = (
            self.exploitation_weight,
            self.impact_weight,
            self.exposure_weight,
            self.credibility_weight,
            self.freshness_weight,
        )
        if any(weight < 0.0 or weight > 1.0 for weight in weights):
            raise ValueError("dimension weights must be within [0, 1]")
        if abs(sum(weights) - 1.0) > 1e-9:
            raise ValueError("dimension weights must sum to 1.0")
        if not 0.0 <= self.neutral_source_trust <= 1.0:
            raise ValueError("neutral_source_trust must be within [0, 1]")
        if not 0.0 <= self.summary_confidence_multiplier <= 1.0:
            raise ValueError("summary confidence multiplier must be within [0, 1]")


@dataclass(frozen=True)
class PhraseRule:
    name: str
    pattern: re.Pattern[str]
    score: float
    explanation: str


@dataclass(frozen=True)
class RuleHit:
    rule_name: str
    score: float
    explanation: str
    quote: str | None = None


@dataclass(frozen=True)
class DimensionResult:
    name: str
    score: float
    reasons: tuple[str, ...]
    evidence: tuple[EvidenceItem, ...] = ()
    informative: bool = False


EXPLOITATION_RULES = (
    PhraseRule(
        "active_exploitation",
        re.compile(
            r"\b(?:actively exploited|active exploitation|exploited in the wild|"
            r"under active attack)\b",
            re.IGNORECASE,
        ),
        1.0,
        "confirmed active exploitation wording",
    ),
    PhraseRule(
        "public_exploit",
        re.compile(r"\b(?:public exploit|exploit code (?:is )?available)\b", re.IGNORECASE),
        0.70,
        "public exploit code wording",
    ),
    PhraseRule(
        "proof_of_concept",
        re.compile(r"\b(?:proof[ -]of[ -]concept|PoC)\b", re.IGNORECASE),
        0.45,
        "proof-of-concept wording",
    ),
)

IMPACT_RULES = (
    PhraseRule(
        "remote_code_execution",
        re.compile(r"\b(?:remote code execution|RCE)\b", re.IGNORECASE),
        1.0,
        "remote code execution impact",
    ),
    PhraseRule(
        "ransomware_or_breach",
        re.compile(r"\b(?:ransomware|data breach)\b", re.IGNORECASE),
        0.90,
        "material ransomware or data-breach impact",
    ),
    PhraseRule(
        "authentication_bypass",
        re.compile(r"\b(?:authentication bypass|auth bypass)\b", re.IGNORECASE),
        0.85,
        "authentication bypass impact",
    ),
    PhraseRule(
        "privilege_escalation",
        re.compile(r"\bprivilege escalation\b", re.IGNORECASE),
        0.75,
        "privilege escalation impact",
    ),
    PhraseRule(
        "denial_of_service",
        re.compile(r"\b(?:denial[ -]of[ -]service|DoS)\b", re.IGNORECASE),
        0.45,
        "denial-of-service impact",
    ),
)

EXPOSURE_RULES = (
    PhraseRule(
        "internet_facing",
        re.compile(r"\b(?:internet[ -]facing|publicly exposed)\b", re.IGNORECASE),
        1.0,
        "internet-facing exposure",
    ),
    PhraseRule(
        "widely_used",
        re.compile(r"\b(?:widely used|widespread deployment|millions of users)\b", re.IGNORECASE),
        0.80,
        "broad deployment wording",
    ),
    PhraseRule(
        "remote_reachability",
        re.compile(
            r"\b(?:remote attacker|network-accessible|without authentication)\b", re.IGNORECASE
        ),
        0.70,
        "remote reachability wording",
    ),
    PhraseRule(
        "local_only",
        re.compile(r"\b(?:requires local access|local attacker)\b", re.IGNORECASE),
        0.20,
        "local-access-only wording",
    ),
)

CVSS_PATTERN = re.compile(
    r"\bCVSS(?:\s*(?:v3(?:\.\d)?|score))?\s*[:=]?\s*"
    r"(10(?:\.0)?|[0-9](?:\.[0-9])?)\b",
    re.IGNORECASE,
)


class DeterministicRiskEvaluator:
    name = "deterministic"

    def __init__(
        self,
        config: DeterministicScoringConfig | None = None,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        timer: Callable[[], float] = perf_counter,
    ) -> None:
        self._config = config or DeterministicScoringConfig()
        self._now = now
        self._timer = timer

    def evaluate(self, context: EvaluationContext) -> RiskResult:
        started_at = self._timer()
        text = "\n".join(f"{article.title}\n{article.content}" for article in context.articles)

        dimensions = (
            self._exploitation(text),
            self._impact(text),
            self._exposure(text),
            self._credibility(context),
            self._freshness(context),
        )
        weights = {
            "exploitation": self._config.exploitation_weight,
            "impact": self._config.impact_weight,
            "exposure": self._config.exposure_weight,
            "credibility": self._config.credibility_weight,
            "freshness": self._config.freshness_weight,
        }
        score = _clamp(sum(dimension.score * weights[dimension.name] for dimension in dimensions))
        reasons = tuple(
            f"{dimension.name}.{reason} "
            f"(dimension={dimension.score:.2f}, "
            f"weighted={dimension.score * weights[dimension.name]:.3f})"
            for dimension in dimensions
            for reason in dimension.reasons
        )
        evidence = _unique_evidence(item for dimension in dimensions for item in dimension.evidence)

        informative_dimensions = sum(dimension.informative for dimension in dimensions)
        source_count = max(1, context.event.corroborating_source_count)
        confidence = 0.35 + 0.10 * informative_dimensions + 0.05 * min(source_count, 3)
        if all(article.content_quality is ContentQuality.LIMITED for article in context.articles):
            confidence *= self._config.summary_confidence_multiplier

        duration_ms = max(0, int(round((self._timer() - started_at) * 1000)))
        return RiskResult(
            evaluator=self.name,
            score=round(_clamp(score), 4),
            confidence=round(_clamp(min(confidence, 0.95)), 4),
            reasons=reasons,
            evidence=evidence,
            duration_ms=duration_ms,
        )

    def _exploitation(self, text: str) -> DimensionResult:
        safe_text = mask_exploitation_negations(text)
        hit = _best_phrase_rule(EXPLOITATION_RULES, safe_text, evidence_text=text)
        if hit is not None:
            return _dimension_from_hit("exploitation", hit)

        for pattern in EXPLOITATION_NEGATIONS:
            match = pattern.search(text)
            if match:
                quote = match.group(0)
                return DimensionResult(
                    name="exploitation",
                    score=0.0,
                    reasons=("negated_exploitation: explicit negation prevents a positive signal",),
                    evidence=(EvidenceItem(quote=quote, verified=True),),
                    informative=True,
                )
        return DimensionResult(name="exploitation", score=0.0, reasons=())

    def _impact(self, text: str) -> DimensionResult:
        candidates = list(_phrase_rule_hits(IMPACT_RULES, text))
        for match in CVSS_PATTERN.finditer(text):
            cvss = min(10.0, max(0.0, float(match.group(1))))
            candidates.append(
                RuleHit(
                    rule_name="explicit_cvss",
                    score=cvss / 10.0,
                    explanation=f"explicit CVSS value {cvss:.1f}",
                    quote=match.group(0),
                )
            )
        return _dimension_from_best("impact", candidates)

    def _exposure(self, text: str) -> DimensionResult:
        return _dimension_from_best("exposure", _phrase_rule_hits(EXPOSURE_RULES, text))

    def _credibility(self, context: EvaluationContext) -> DimensionResult:
        source_names = {article.source_name for article in context.articles}
        configured_trust = [
            context.source_trust_scores[source]
            for source in source_names
            if source in context.source_trust_scores
        ]
        trust = max(configured_trust, default=self._config.neutral_source_trust)
        source_count = max(1, context.event.corroborating_source_count)
        corroboration = 0.40 if source_count == 1 else 0.75 if source_count == 2 else 1.0
        score = _clamp(0.70 * trust + 0.30 * corroboration)
        trust_label = "configured source trust" if configured_trust else "neutral source trust"
        return DimensionResult(
            name="credibility",
            score=score,
            reasons=(
                f"source_trust_and_corroboration: {trust_label} {trust:.2f}; "
                f"{source_count} independent source(s)",
            ),
            informative=True,
        )

    def _freshness(self, context: EvaluationContext) -> DimensionResult:
        published_at = [
            _as_utc(article.published_at)
            for article in context.articles
            if article.published_at is not None
        ]
        if not published_at:
            return DimensionResult(
                name="freshness",
                score=0.0,
                reasons=("publication_time_missing: no publication timestamp",),
            )

        newest = max(published_at)
        age = max(timedelta(0), _as_utc(self._now()) - newest)
        if age <= timedelta(days=1):
            score, label = 1.0, "at most 1 day old"
        elif age <= timedelta(days=7):
            score, label = 0.80, "at most 7 days old"
        elif age <= timedelta(days=30):
            score, label = 0.50, "at most 30 days old"
        elif age <= timedelta(days=90):
            score, label = 0.20, "at most 90 days old"
        else:
            score, label = 0.0, "older than 90 days"
        return DimensionResult(
            name="freshness",
            score=score,
            reasons=(f"publication_age: {label}",),
            informative=True,
        )


def _phrase_rule_hits(rules: Iterable[PhraseRule], text: str) -> Iterable[RuleHit]:
    for rule in rules:
        match = rule.pattern.search(text)
        if match:
            yield RuleHit(
                rule_name=rule.name,
                score=rule.score,
                explanation=rule.explanation,
                quote=match.group(0),
            )


def _best_phrase_rule(
    rules: Iterable[PhraseRule],
    text: str,
    *,
    evidence_text: str | None = None,
) -> RuleHit | None:
    candidates: list[RuleHit] = []
    for rule in rules:
        match = rule.pattern.search(text)
        if match:
            source = evidence_text or text
            candidates.append(
                RuleHit(
                    rule_name=rule.name,
                    score=rule.score,
                    explanation=rule.explanation,
                    quote=source[match.start() : match.end()],
                )
            )
    return max(candidates, key=lambda hit: hit.score, default=None)


def _dimension_from_best(name: str, hits: Iterable[RuleHit]) -> DimensionResult:
    hit = max(hits, key=lambda candidate: candidate.score, default=None)
    if hit is None:
        return DimensionResult(name=name, score=0.0, reasons=())
    return _dimension_from_hit(name, hit)


def _dimension_from_hit(name: str, hit: RuleHit) -> DimensionResult:
    evidence = (EvidenceItem(quote=hit.quote, verified=True),) if hit.quote else ()
    return DimensionResult(
        name=name,
        score=_clamp(hit.score),
        reasons=(f"{hit.rule_name}: {hit.explanation}",),
        evidence=evidence,
        informative=True,
    )


def _unique_evidence(items: Iterable[EvidenceItem]) -> tuple[EvidenceItem, ...]:
    unique: list[EvidenceItem] = []
    seen: set[str] = set()
    for item in items:
        normalized = item.quote.casefold()
        if normalized not in seen:
            seen.add(normalized)
            unique.append(item)
    return tuple(unique)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _clamp(value: float) -> float:
    return min(1.0, max(0.0, value))
