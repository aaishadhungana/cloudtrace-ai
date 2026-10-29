import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, UUIDPrimaryKey, string_enum
from app.models.enums import AnalysisStatus

if TYPE_CHECKING:
    from app.models.attack_path import AttackPath
    from app.models.environment import Environment
    from app.models.finding import Finding


class AnalysisRun(UUIDPrimaryKey, Base):
    __tablename__ = "analysis_runs"

    environment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("environments.id", ondelete="CASCADE"), index=True
    )
    import_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("imports.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[AnalysisStatus] = mapped_column(
        string_enum(AnalysisStatus), default=AnalysisStatus.PENDING
    )
    analysis_version: Mapped[str] = mapped_column(String(32))
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finding_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")

    environment: Mapped["Environment"] = relationship(back_populates="analysis_runs")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="analysis_run", cascade="all, delete-orphan", passive_deletes=True
    )
    attack_paths: Mapped[list["AttackPath"]] = relationship(
        back_populates="analysis_run", cascade="all, delete-orphan", passive_deletes=True
    )