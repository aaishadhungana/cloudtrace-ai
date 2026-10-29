import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, CreatedAt, UUIDPrimaryKey, string_enum
from app.models.enums import ValidationStatus

if TYPE_CHECKING:
    from app.models.environment import Environment


class ImportRecord(UUIDPrimaryKey, CreatedAt, Base):
    __tablename__ = "imports"

    environment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("environments.id", ondelete="CASCADE"), index=True
    )
    import_source: Mapped[str] = mapped_column(String(255))
    schema_version: Mapped[str] = mapped_column(String(32))
    validation_status: Mapped[ValidationStatus] = mapped_column(
        string_enum(ValidationStatus), default=ValidationStatus.PENDING
    )
    sanitized_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    environment: Mapped["Environment"] = relationship(back_populates="imports")