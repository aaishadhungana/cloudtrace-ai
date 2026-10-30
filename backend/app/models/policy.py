import uuid
from typing import Any

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, CreatedAt, UUIDPrimaryKey


class Policy(UUIDPrimaryKey, CreatedAt, Base):
    __tablename__ = "policies"
    __table_args__ = (UniqueConstraint("import_id", "external_id"),)

    import_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("imports.id", ondelete="CASCADE"), index=True
    )
    external_id: Mapped[str] = mapped_column(String(255))
    name: Mapped[str] = mapped_column(String(255))
    statements: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)