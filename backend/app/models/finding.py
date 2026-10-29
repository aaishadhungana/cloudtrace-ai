import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import CheckConstraint, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, CreatedAt, UUIDPrimaryKey, string_enum
from app.models.enums import FindingStatus, Severity

if TYPE_CHECKING:
    from app.models.analysis_run import AnalysisRun


class Finding(UUIDPrimaryKey, CreatedAt, Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("analysis_run_id", "fingerprint"),
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="risk_score_range"),
    )

    analysis_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="CASCADE"), index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64))
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    finding_type: Mapped[str] = mapped_column(String(64))
    severity: Mapped[Severity] = mapped_column(string_enum(Severity), index=True)
    risk_score: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(255))
    identity_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("identities.id", ondelete="SET NULL")
    )
    resource_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("resources.id", ondelete="SET NULL")
    )
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    risk_factors: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    explanation: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text)
    status: Mapped[FindingStatus] = mapped_column(
        string_enum(FindingStatus), default=FindingStatus.OPEN
    )

    analysis_run: Mapped["AnalysisRun"] = relationship(back_populates="findings")