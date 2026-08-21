from collections.abc import Callable
from decimal import Decimal

from threat_alerting.application.alerting.matching import ProfileMatcher
from threat_alerting.domain import (
    Alert,
    AlertDecisionOutcome,
    AlertDecisionResult,
    AlertStatus,
    Assessment,
    AssessmentStatus,
    ClientProfile,
    NewsArticle,
    ProfileMatchResult,
    ThreatEvent,
)
from threat_alerting.domain.ports import AlertUnitOfWork


class AlertDecisionService:
    def __init__(
        self,
        unit_of_work_factory: Callable[[], AlertUnitOfWork],
        *,
        matcher: ProfileMatcher | None = None,
        disagreement_review_threshold: float = 0.40,
        borderline_margin: float = 0.05,
        invalid_evidence_high_score_threshold: float = 0.70,
    ) -> None:
        thresholds = (
            disagreement_review_threshold,
            borderline_margin,
            invalid_evidence_high_score_threshold,
        )
        if any(value < 0.0 or value > 1.0 for value in thresholds):
            raise ValueError("decision review thresholds must be within [0, 1]")
        self._unit_of_work_factory = unit_of_work_factory
        self._matcher = matcher or ProfileMatcher()
        self._disagreement_review_threshold = disagreement_review_threshold
        self._borderline_margin = borderline_margin
        self._invalid_evidence_high_score_threshold = invalid_evidence_high_score_threshold

    def decide(self, profile_id: int, assessment_id: int) -> AlertDecisionResult:
        with self._unit_of_work_factory() as unit_of_work:
            profile = unit_of_work.client_profiles.get(profile_id)
            if profile is None:
                raise LookupError(f"client profile {profile_id} does not exist")
            assessment = unit_of_work.assessments.get(assessment_id)
            if assessment is None:
                raise LookupError(f"assessment {assessment_id} does not exist")
            event = unit_of_work.threat_events.get(assessment.event_id)
            if event is None:
                raise LookupError(f"threat event {assessment.event_id} does not exist")
            articles = tuple(unit_of_work.news_articles.list_for_event(event.id))
            existing_alert = unit_of_work.alerts.get_for_profile_assessment(
                profile_id,
                assessment_id,
            )

        if existing_alert is not None:
            return _existing_alert_decision(existing_alert)
        if assessment.status is not AssessmentStatus.COMPLETE:
            return self._reject(
                profile,
                assessment,
                event,
                articles,
                reason_codes=("assessment_incomplete",),
            )
        if not profile.enabled:
            return self._reject(
                profile,
                assessment,
                event,
                articles,
                reason_codes=("profile_disabled",),
            )

        match = self._matcher.match(profile, event)
        if not match.matched:
            return self._reject(
                profile,
                assessment,
                event,
                articles,
                match=match,
                reason_codes=match.reason_codes,
            )

        assert assessment.average_score is not None
        margin = _subtract(assessment.average_score, profile.minimum_score)
        review_reasons = self._review_reasons(assessment, margin)
        if assessment.average_score <= profile.minimum_score:
            threshold_reason = (
                "score_equal_to_threshold"
                if assessment.average_score == profile.minimum_score
                else "score_below_threshold"
            )
            return self._reject(
                profile,
                assessment,
                event,
                articles,
                match=match,
                reason_codes=(*match.reason_codes, threshold_reason),
                margin=margin,
                review_reasons=review_reasons,
            )

        reason_codes = (*match.reason_codes, "score_above_threshold")
        certificate = _build_decision_certificate(
            profile=profile,
            assessment=assessment,
            event=event,
            articles=articles,
            match=match,
            outcome=AlertDecisionOutcome.ALERT,
            reason_codes=reason_codes,
            margin=margin,
            review_reasons=review_reasons,
        )
        alert = Alert(
            profile_id=_required_id(profile.id, "profile"),
            assessment_id=_required_id(assessment.id, "assessment"),
            event_id=_required_id(event.id, "event"),
            title=f"Threat alert: {event.cve_id or event.event_key}",
            summary=(
                f"Risk score {assessment.average_score:.4f} exceeded "
                f"profile threshold {profile.minimum_score:.4f}."
            ),
            average_score=assessment.average_score,
            threshold=profile.minimum_score,
            decision_margin=margin,
            needs_review=bool(review_reasons),
            decision_certificate=certificate,
            status=AlertStatus.PENDING,
        )
        with self._unit_of_work_factory() as unit_of_work:
            stored, created = unit_of_work.alerts.add_or_get(alert)
            unit_of_work.commit()

        if not created:
            return _existing_alert_decision(stored)

        return AlertDecisionResult(
            outcome=AlertDecisionOutcome.ALERT,
            profile_id=profile_id,
            assessment_id=assessment_id,
            average_score=stored.average_score,
            threshold=stored.threshold,
            decision_margin=stored.decision_margin,
            matched_by=match.matched_by,
            reason_codes=reason_codes,
            review_reasons=review_reasons,
            needs_review=stored.needs_review,
            decision_certificate=stored.decision_certificate,
            alert=stored,
            alert_created=created,
        )

    def _reject(
        self,
        profile: ClientProfile,
        assessment: Assessment,
        event: ThreatEvent,
        articles: tuple[NewsArticle, ...],
        *,
        reason_codes: tuple[str, ...],
        match: ProfileMatchResult | None = None,
        margin: float | None = None,
        review_reasons: tuple[str, ...] = (),
    ) -> AlertDecisionResult:
        match = match or ProfileMatchResult(matched=False, reason_codes=reason_codes)
        certificate = _build_decision_certificate(
            profile=profile,
            assessment=assessment,
            event=event,
            articles=articles,
            match=match,
            outcome=AlertDecisionOutcome.NO_ALERT,
            reason_codes=reason_codes,
            margin=margin,
            review_reasons=review_reasons,
        )
        return AlertDecisionResult(
            outcome=AlertDecisionOutcome.NO_ALERT,
            profile_id=_required_id(profile.id, "profile"),
            assessment_id=_required_id(assessment.id, "assessment"),
            average_score=assessment.average_score,
            threshold=profile.minimum_score,
            decision_margin=margin,
            matched_by=match.matched_by,
            reason_codes=reason_codes,
            review_reasons=review_reasons,
            needs_review=bool(review_reasons),
            decision_certificate=certificate,
        )

    def _review_reasons(self, assessment: Assessment, margin: float) -> tuple[str, ...]:
        reasons = []
        assert assessment.score_disagreement is not None
        if assessment.score_disagreement >= self._disagreement_review_threshold:
            reasons.append("high_score_disagreement")
        if abs(margin) <= self._borderline_margin:
            reasons.append("borderline_threshold_margin")
        for result in assessment.evaluator_results:
            if (
                result.provider is not None
                and result.score >= self._invalid_evidence_high_score_threshold
                and not any(item.verified for item in result.evidence)
            ):
                reasons.append(f"invalid_high_score_evidence:{result.evaluator}")
        return tuple(reasons)


def _existing_alert_decision(alert: Alert) -> AlertDecisionResult:
    certificate = alert.decision_certificate
    decision = certificate.get("decision", {})
    profile = certificate.get("profile", {})
    return AlertDecisionResult(
        outcome=AlertDecisionOutcome.ALERT,
        profile_id=alert.profile_id,
        assessment_id=alert.assessment_id,
        average_score=alert.average_score,
        threshold=alert.threshold,
        decision_margin=alert.decision_margin,
        matched_by=tuple(profile.get("matched_by", ())),
        reason_codes=tuple(decision.get("reason_codes", ("score_above_threshold",))),
        review_reasons=tuple(decision.get("review_reasons", ())),
        needs_review=alert.needs_review,
        decision_certificate=certificate,
        alert=alert,
        alert_created=False,
    )


def _build_decision_certificate(
    *,
    profile: ClientProfile,
    assessment: Assessment,
    event: ThreatEvent,
    articles: tuple[NewsArticle, ...],
    match: ProfileMatchResult,
    outcome: AlertDecisionOutcome,
    reason_codes: tuple[str, ...],
    margin: float | None,
    review_reasons: tuple[str, ...],
) -> dict:
    evidence = [
        {
            "evaluator": result.evaluator,
            "quote": item.quote,
            "verified": item.verified,
        }
        for result in assessment.evaluator_results
        for item in result.evidence
    ]
    evaluator_provenance = {
        result.evaluator: {
            "confidence": result.confidence,
            "provider": result.provider,
            "model": result.model,
            "prompt_version": result.prompt_version,
            "attempt_count": result.attempt_count,
            "duration_ms": result.duration_ms,
        }
        for result in assessment.evaluator_results
    }
    return {
        "profile": {
            "id": profile.id,
            "name": profile.name,
            "threshold": profile.minimum_score,
            "filters": {
                "vendors": list(profile.vendors),
                "products": list(profile.products),
                "categories": list(profile.categories),
            },
            "matched_by": list(match.matched_by),
        },
        "event": {
            "id": event.id,
            "event_key": event.event_key,
            "cve_id": event.cve_id,
            "source_count": event.corroborating_source_count,
            "articles": [
                {
                    "id": article.id,
                    "source": article.source_name,
                    "url": article.canonical_url,
                }
                for article in articles
            ],
        },
        "assessment": {
            "id": assessment.id,
            "version": assessment.assessment_version,
            "status": assessment.status.value,
            "content_quality": assessment.content_quality.value,
            "scores": {result.evaluator: result.score for result in assessment.evaluator_results},
            "average_score": assessment.average_score,
            "score_disagreement": assessment.score_disagreement,
            "evidence": evidence,
            "provenance": {
                "evaluators": evaluator_provenance,
                "model_metadata": assessment.model_metadata,
                "prompt_versions": assessment.prompt_versions,
            },
        },
        "decision": {
            "outcome": outcome.value,
            "threshold": profile.minimum_score,
            "margin": margin,
            "reason_codes": list(reason_codes),
            "review_reasons": list(review_reasons),
            "needs_review": bool(review_reasons),
        },
    }


def _subtract(left: float, right: float) -> float:
    return float(Decimal(str(left)) - Decimal(str(right)))


def _required_id(value: int | None, entity: str) -> int:
    if value is None:
        raise ValueError(f"persisted {entity} requires an id")
    return value
