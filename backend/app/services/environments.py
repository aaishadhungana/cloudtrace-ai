from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Environment, User
from app.schemas.environment import EnvironmentCreate, EnvironmentUpdate


class EnvironmentNameTakenError(Exception):
    pass


def _commit_unique(db: Session) -> None:
    try:
        db.commit()
    except IntegrityError as error:
        db.rollback()
        raise EnvironmentNameTakenError from error


def create_environment(db: Session, owner: User, payload: EnvironmentCreate) -> Environment:
    environment = Environment(
        owner_id=owner.id,
        name=payload.name,
        cloud_provider=payload.cloud_provider,
        description=payload.description,
    )
    db.add(environment)
    _commit_unique(db)
    db.refresh(environment)
    return environment


def list_environments(db: Session, owner: User) -> list[Environment]:
    statement = (
        select(Environment)
        .where(Environment.owner_id == owner.id)
        .order_by(Environment.created_at.desc())
    )
    return list(db.scalars(statement))


def update_environment(
    db: Session, environment: Environment, payload: EnvironmentUpdate
) -> Environment:
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(environment, field, value)
    _commit_unique(db)
    db.refresh(environment)
    return environment


def delete_environment(db: Session, environment: Environment) -> None:
    db.delete(environment)
    db.commit()