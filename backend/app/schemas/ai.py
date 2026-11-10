import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel

from app.models.enums import AISubjectType

AI_NOTICE = (
    "AI-generated explanation. It is not verified evidence and does not change findings, "
    "scores or attack paths."
)


class AIStatus(BaseModel):
    available: bool
    model: str | None
    reason: str | None


class AIAnalysisRead(BaseModel):
    subject_type: AISubjectType
    subject_id: uuid.UUID | None
    model: str
    generated_at: datetime
    cached: bool
    notice: str = AI_NOTICE
    content: dict[str, Any]