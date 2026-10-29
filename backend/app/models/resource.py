import uuid
from typing import Any

from sqlalchemy import Boolean, ForeignKey, String, UniqueConstraint, false
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, CreatedAt, UUIDPrimaryKey, string_enum
from app.models.enums import ResourceType


class Resource(UUIDPrimaryKey, CreatedAt, Base):
    __tablename__ = "resources"
    __table_args__ = (UniqueConstraint("import_id", "external_id"),)

    import_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("imports.id", ondelete="CASCADE"), index=True
    )
    external_id: Mapped[str] = mapped_column(String(255))
    name: Mapped[str] = mapped_column(String(255))
    resource_type: Mapped[ResourceType] = mapped_column(string_enum(ResourceType))
    is_sensitive: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=false()
    )
    attributes: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)