import json
import logging
from functools import lru_cache
from typing import Any

import httpx
from google import genai
from google.genai import errors as genai_errors
from google.genai import types
from pydantic import BaseModel, ValidationError

from app.ai.analyst import Analyst
from app.ai.errors import (
    AIError,
    AIInvalidResponseError,
    AINotConfiguredError,
    AIProviderError,
    AIQuotaError,
    AITimeoutError,
)
from app.ai.schemas import check_limits
from app.core.config import Settings, get_settings

logger = logging.getLogger(__name__)

NOT_CONFIGURED_MESSAGE = "Gemini is not configured. Set GEMINI_API_KEY and GEMINI_MODEL."
TIMEOUT_STATUS_CODES = frozenset({408, 504})
CREDENTIAL_STATUS_CODES = frozenset({401, 403})


@lru_cache(maxsize=4)
def _build_client(api_key: str, timeout_ms: int) -> genai.Client:
    return genai.Client(api_key=api_key, http_options=types.HttpOptions(timeout=timeout_ms))


def map_api_error(error: genai_errors.APIError) -> AIError:
    code = getattr(error, "code", None)
    logger.warning("Gemini API returned status %s", code)
    if code == 429:
        return AIQuotaError("The AI provider quota or rate limit was reached. Try again later.")
    if code in TIMEOUT_STATUS_CODES:
        return AITimeoutError("The AI provider took too long to respond.")
    if code in CREDENTIAL_STATUS_CODES:
        return AIProviderError(
            "The AI provider rejected the configured API key or model access."
        )
    if code == 404:
        return AIProviderError(
            "The configured model was not found or is not available to this API key."
        )
    if code == 400:
        return AIProviderError("The AI provider rejected the request.")
    return AIProviderError("The AI provider returned an error.")


def parse_output[T: BaseModel](text: str | None, schema: type[T]) -> T:
    if not text:
        raise AIInvalidResponseError("The AI provider returned an empty response.")
    try:
        result = schema.model_validate_json(text)
    except ValidationError as error:
        raise AIInvalidResponseError(
            "The AI response did not match the expected structure."
        ) from error
    check_limits(result)
    return result


class GeminiAnalyst(Analyst):
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    @property
    def model_name(self) -> str:
        return self._settings.gemini_model

    @property
    def is_configured(self) -> bool:
        return bool(self._settings.gemini_api_key and self._settings.gemini_model)

    def generate[T: BaseModel](
        self, system_instruction: str, payload: dict[str, Any], schema: type[T]
    ) -> T:
        if not self.is_configured:
            raise AINotConfiguredError(NOT_CONFIGURED_MESSAGE)
        client = _build_client(
            self._settings.gemini_api_key, self._settings.gemini_timeout_seconds * 1000
        )
        config = types.GenerateContentConfig(
            system_instruction=system_instruction,
            response_mime_type="application/json",
            response_schema=schema,
            temperature=0.2,
            max_output_tokens=self._settings.gemini_max_output_tokens,
        )
        try:
            response = client.models.generate_content(
                model=self._settings.gemini_model,
                contents=json.dumps(payload, sort_keys=True, ensure_ascii=False),
                config=config,
            )
        except genai_errors.APIError as error:
            raise map_api_error(error) from error
        except httpx.TimeoutException as error:
            raise AITimeoutError("The AI provider took too long to respond.") from error
        except httpx.HTTPError as error:
            logger.warning("Gemini request failed: %s", type(error).__name__)
            raise AIProviderError("The AI provider could not be reached.") from error
        return parse_output(getattr(response, "text", None), schema)


def get_analyst() -> Analyst:
    return GeminiAnalyst(get_settings())