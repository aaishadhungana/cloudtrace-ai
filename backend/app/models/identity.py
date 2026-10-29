import uuid
from typing import Any

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, CreatedAt, UUIDPrimaryKey, string_enum
from app.models.enums import IdentityType


class Identity(UUIDPrimaryKey, CreatedAt, Base):
    __tablename__ = "identities"
    __table_args__ = (UniqueConstraint("import_id", "external_id"),)

    import_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("imports.id", ondelete="CASCADE"), index=True
    )
    external_id: Mapped[str] = mapped_column(String(255))
    name: Mapped[str] = mapped_column(String(255))
    identity_type: Mapped[IdentityType] = mapped_column(string_enum(IdentityType))
    account_id: Mapped[str | None] = mapped_column(String(32))
    attributes: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)