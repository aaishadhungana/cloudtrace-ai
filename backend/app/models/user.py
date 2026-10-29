from typing import TYPE_CHECKING

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, CreatedAt, UUIDPrimaryKey

if TYPE_CHECKING:
    from app.models.environment import Environment


class User(UUIDPrimaryKey, CreatedAt, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))

    environments: Mapped[list["Environment"]] = relationship(
        back_populates="owner", cascade="all, delete-orphan", passive_deletes=True
    )