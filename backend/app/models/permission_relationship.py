import uuid
from typing import Any

from sqlalchemy import CheckConstraint, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, CreatedAt, UUIDPrimaryKey, string_enum
from app.models.enums import Decision, Effect, RelationshipType


class PermissionRelationship(UUIDPrimaryKey, CreatedAt, Base):
    __tablename__ = "permission_relationships"
    __table_args__ = (
        CheckConstraint(
            "(target_identity_id IS NULL) <> (target_resource_id IS NULL)",
            name="exactly_one_target",
        ),
    )

    analysis_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="CASCADE"), index=True
    )
    source_identity_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("identities.id", ondelete="CASCADE"), index=True
    )
    target_identity_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("identities.id", ondelete="CASCADE"), index=True
    )
    target_resource_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("resources.id", ondelete="CASCADE"), index=True
    )
    relationship_type: Mapped[RelationshipType] = mapped_column(string_enum(RelationshipType))
    effect: Mapped[Effect] = mapped_column(string_enum(Effect))
    decision: Mapped[Decision] = mapped_column(string_enum(Decision))
    conditions: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)