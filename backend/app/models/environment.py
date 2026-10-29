import uuid
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, CreatedAt, UUIDPrimaryKey, string_enum
from app.models.enums import CloudProvider

if TYPE_CHECKING:
    from app.models.analysis_run import AnalysisRun
    from app.models.import_record import ImportRecord
    from app.models.user import User


class Environment(UUIDPrimaryKey, CreatedAt, Base):
    __tablename__ = "environments"
    __table_args__ = (UniqueConstraint("owner_id", "name"),)

    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(120))
    cloud_provider: Mapped[CloudProvider] = mapped_column(
        string_enum(CloudProvider), default=CloudProvider.AWS
    )
    description: Mapped[str | None] = mapped_column(Text)

    owner: Mapped["User"] = relationship(back_populates="environments")
    imports: Mapped[list["ImportRecord"]] = relationship(
        back_populates="environment", cascade="all, delete-orphan", passive_deletes=True
    )
    analysis_runs: Mapped[list["AnalysisRun"]] = relationship(
        back_populates="environment", cascade="all, delete-orphan", passive_deletes=True
    )