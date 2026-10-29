import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import CheckConstraint, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, CreatedAt, UUIDPrimaryKey, string_enum
from app.models.enums import PathClassification

if TYPE_CHECKING:
    from app.models.analysis_run import AnalysisRun


class AttackPath(UUIDPrimaryKey, CreatedAt, Base):
    __tablename__ = "attack_paths"
    __table_args__ = (
        UniqueConstraint("analysis_run_id", "fingerprint"),
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="risk_score_range"),
    )

    analysis_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="CASCADE"), index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64))
    start_identity_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("identities.id", ondelete="CASCADE"), index=True
    )
    target_resource_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("resources.id", ondelete="CASCADE"), index=True
    )
    nodes: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    edges: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    risk_score: Mapped[int] = mapped_column(Integer)
    classification: Mapped[PathClassification] = mapped_column(string_enum(PathClassification))

    analysis_run: Mapped["AnalysisRun"] = relationship(back_populates="attack_paths")