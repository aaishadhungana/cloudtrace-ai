from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    gemini_api_key: str = ""
    gemini_model: str = ""
    gemini_timeout_seconds: int = Field(default=30, ge=5, le=120)
    gemini_max_output_tokens: int = Field(default=8192, ge=512, le=65536)
    ai_max_prompt_chars: int = Field(default=16000, ge=2000)

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()