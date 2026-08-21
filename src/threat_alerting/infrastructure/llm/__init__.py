from threat_alerting.domain.ports import LLMProvider
from threat_alerting.infrastructure.llm.fake_provider import FakeLLMProvider
from threat_alerting.infrastructure.llm.openai_provider import OpenAILLMProvider
from threat_alerting.settings import Settings


def create_llm_provider(settings: Settings) -> LLMProvider:
    if settings.llm_provider == "fake":
        return FakeLLMProvider()

    api_key = settings.llm_api_key.get_secret_value() if settings.llm_api_key else ""
    if not api_key:
        raise ValueError("LLM_API_KEY is required when LLM_PROVIDER=openai")
    return OpenAILLMProvider(
        api_key=api_key,
        model=settings.llm_model,
        max_output_tokens=settings.llm_max_output_tokens,
        timeout_seconds=settings.llm_timeout_seconds,
    )


__all__ = ["FakeLLMProvider", "OpenAILLMProvider", "create_llm_provider"]
