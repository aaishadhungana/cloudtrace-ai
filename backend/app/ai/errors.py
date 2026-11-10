class AIError(Exception):
    code = "ai_error"
    http_status = 502

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class AINotConfiguredError(AIError):
    code = "ai_not_configured"
    http_status = 503


class AIQuotaError(AIError):
    code = "ai_quota_exceeded"
    http_status = 429


class AITimeoutError(AIError):
    code = "ai_timeout"
    http_status = 504


class AIProviderError(AIError):
    code = "ai_provider_error"
    http_status = 502


class AIInvalidResponseError(AIError):
    code = "ai_invalid_response"
    http_status = 502