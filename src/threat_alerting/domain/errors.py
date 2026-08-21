class LLMProviderError(RuntimeError):
    pass


class TransientLLMProviderError(LLMProviderError):
    pass


class PermanentLLMProviderError(LLMProviderError):
    pass


class InvalidLLMResponseError(LLMProviderError):
    pass


class EvaluatorExecutionError(RuntimeError):
    def __init__(self, evaluator: str, reason: str, attempts: int) -> None:
        self.evaluator = evaluator
        self.reason = reason
        self.attempts = attempts
        super().__init__(f"{evaluator} failed after {attempts} attempt(s): {reason}")
