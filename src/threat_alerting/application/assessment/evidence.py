import re

from threat_alerting.domain import EvaluationContext, EvidenceItem, StructuredLLMResult

_WHITESPACE = re.compile(r"\s+")


def validate_evidence(
    result: StructuredLLMResult,
    context: EvaluationContext,
) -> tuple[EvidenceItem, ...]:
    article_texts = tuple(
        _normalize(f"{article.title}\n{article.content}") for article in context.articles
    )
    return tuple(
        EvidenceItem(
            quote=item.quote,
            verified=any(_normalize(item.quote) in article for article in article_texts),
        )
        for item in result.evidence
    )


def _normalize(value: str) -> str:
    return _WHITESPACE.sub(" ", value).strip().casefold()
