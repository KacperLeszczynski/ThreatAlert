from typing import Any

from openai import APIConnectionError, APIStatusError, APITimeoutError, OpenAI, RateLimitError
from pydantic import ValidationError

from threat_alerting.domain import LLMRequest, StructuredLLMResult
from threat_alerting.domain.errors import (
    InvalidLLMResponseError,
    PermanentLLMProviderError,
    TransientLLMProviderError,
)


class OpenAILLMProvider:
    name = "openai"

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        max_output_tokens: int = 2_000,
        timeout_seconds: float = 30.0,
        client: Any | None = None,
    ) -> None:
        if not api_key and client is None:
            raise ValueError("OpenAI API key is required for the openai provider")
        self.model = model
        self._max_output_tokens = max_output_tokens
        self._client = client or OpenAI(
            api_key=api_key,
            max_retries=0,
            timeout=timeout_seconds,
        )

    def evaluate(self, request: LLMRequest) -> StructuredLLMResult:
        trusted_instructions = request.system_instructions
        if request.repair_instruction:
            trusted_instructions = f"{trusted_instructions}\n{request.repair_instruction}"

        try:
            response = self._client.responses.parse(
                model=self.model,
                input=[
                    {"role": "system", "content": trusted_instructions},
                    {"role": "user", "content": request.untrusted_content},
                ],
                text_format=StructuredLLMResult,
                max_output_tokens=self._max_output_tokens,
            )
            parsed = _parsed_output(response)
            return StructuredLLMResult.model_validate(parsed)
        except (RateLimitError, APITimeoutError, APIConnectionError) as exc:
            raise TransientLLMProviderError(str(exc)) from exc
        except APIStatusError as exc:
            if exc.status_code == 429 or exc.status_code >= 500:
                raise TransientLLMProviderError(str(exc)) from exc
            raise PermanentLLMProviderError(str(exc)) from exc
        except ValidationError as exc:
            raise InvalidLLMResponseError(str(exc)) from exc


def _parsed_output(response: Any) -> StructuredLLMResult:
    for output in response.output:
        if getattr(output, "type", None) != "message":
            continue
        for item in output.content:
            parsed = getattr(item, "parsed", None)
            if parsed is not None:
                return parsed
    raise InvalidLLMResponseError("provider returned no parsed structured output")
