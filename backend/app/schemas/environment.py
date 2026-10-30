import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import CloudProvider


class EnvironmentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=120)
    cloud_provider: CloudProvider = CloudProvider.AWS
    description: str | None = Field(default=None, max_length=2000)


class EnvironmentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)

    @field_validator("name")
    @classmethod
    def name_cannot_be_null(cls, value: str | None) -> str:
        if value is None:
            raise ValueError("name cannot be null")
        return value


class EnvironmentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    cloud_provider: CloudProvider
    description: str | None
    created_at: datetime