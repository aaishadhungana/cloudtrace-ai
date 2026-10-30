import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models.enums import ValidationStatus


class ImportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    environment_id: uuid.UUID
    import_source: str
    schema_version: str
    validation_status: ValidationStatus
    sanitized_metadata: dict[str, Any]
    created_at: datetime