from types import SimpleNamespace

from threat_alerting.domain import LLMRequest, StructuredLLMResult
from threat_alerting.infrastructure.llm import OpenAILLMProvider


class ControlledResponses:
    def __init__(self, parsed: StructuredLLMResult) -> None:
        self._parsed = parsed
        self.arguments = None

    def parse(self, **kwargs):
        self.arguments = kwargs
        content = SimpleNamespace(parsed=self._parsed)
        message = SimpleNamespace(type="message", content=[content])
        return SimpleNamespace(output=[message])


def test_openai_adapter_uses_structured_output_and_separate_roles() -> None:
    structured = StructuredLLMResult(
        score=0.7,
        confidence=0.8,
        reasons=("Material impact.",),
        evidence=(),
    )
    responses = ControlledResponses(structured)
    client = SimpleNamespace(responses=responses)
    provider = OpenAILLMProvider(api_key="", model="controlled-model", client=client)
    request = LLMRequest(
        evaluator="impact_expert",
        prompt_version="impact-v1",
        system_instructions="Trusted instructions.",
        untrusted_content="Untrusted article content.",
    )

    result = provider.evaluate(request)

    assert result == structured
    assert responses.arguments is not None
    assert responses.arguments["text_format"] is StructuredLLMResult
    assert responses.arguments["max_output_tokens"] == 2_000
    assert [item["role"] for item in responses.arguments["input"]] == ["system", "user"]
    assert "tools" not in responses.arguments
