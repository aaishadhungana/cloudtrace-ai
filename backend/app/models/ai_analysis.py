import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UUIDPrimaryKey, string_enum
from app.models.enums import AISubjectType


class AIAnalysis(UUIDPrimaryKey, Base):
    __tablename__ = "ai_analyses"
    __table_args__ = (UniqueConstraint("analysis_run_id", "subject_type", "subject_key"),)

    analysis_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="CASCADE"), index=True
    )
    subject_type: Mapped[AISubjectType] = mapped_column(string_enum(AISubjectType))
    subject_key: Mapped[str] = mapped_column(String(64))
    model: Mapped[str] = mapped_column(String(100))
    input_hash: Mapped[str] = mapped_column(String(64))
    content: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )