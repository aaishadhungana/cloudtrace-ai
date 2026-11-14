from functools import lru_cache
from typing import Self

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PLACEHOLDER_SECRETS = frozenset(
    {
        "generate_a_long_random_value_before_starting",
        "change_me",
        "changeme",
        "secret",
        "your_secret_here",
    }
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "CloudTrace AI"
    app_version: str = "0.1.0"
    app_env: str = "development"
    database_url: str
    cors_origins: str = "http://localhost:3000"
    jwt_secret_key: str = Field(min_length=32)
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = Field(default=30, ge=1, le=1440)
    import_max_bytes: int = Field(default=1_048_576, ge=1024)
    max_request_bytes: int = Field(default=2_097_152, ge=1024)
    rate_limit_enabled: bool = True
    trust_proxy_headers: bool = False
    gemini_api_key: str = ""
    gemini_model: str = ""
    gemini_timeout_seconds: int = Field(default=30, ge=5, le=120)
    gemini_max_output_tokens: int = Field(default=8192, ge=512, le=65536)
    ai_max_prompt_chars: int = Field(default=16000, ge=2000)

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"

    @model_validator(mode="after")
    def check_security_settings(self) -> Self:
        if self.jwt_secret_key.lower() in PLACEHOLDER_SECRETS:
            raise ValueError(
                "JWT_SECRET_KEY still has a placeholder value. Generate a long random secret."
            )
        origins = self.cors_origin_list
        if "*" in origins:
            raise ValueError("CORS_ORIGINS must list explicit origins, not '*'.")
        if self.is_production and any(not origin.startswith("https://") for origin in origins):
            raise ValueError("CORS_ORIGINS must use https in production.")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()