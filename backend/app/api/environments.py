from fastapi import APIRouter, HTTPException, Response, status

from app.api.deps import CurrentUser, DbSession, OwnedEnvironment
from app.models import Environment
from app.schemas.environment import EnvironmentCreate, EnvironmentRead, EnvironmentUpdate
from app.services.environments import (
    EnvironmentNameTakenError,
    create_environment,
    delete_environment,
    list_environments,
    update_environment,
)

router = APIRouter(prefix="/environments", tags=["environments"])

NAME_TAKEN_DETAIL = "An environment with this name already exists"


@router.post("", response_model=EnvironmentRead, status_code=status.HTTP_201_CREATED)
def create(payload: EnvironmentCreate, user: CurrentUser, db: DbSession) -> Environment:
    try:
        return create_environment(db, user, payload)
    except EnvironmentNameTakenError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, NAME_TAKEN_DETAIL) from error


@router.get("", response_model=list[EnvironmentRead])
def read_all(user: CurrentUser, db: DbSession) -> list[Environment]:
    return list_environments(db, user)


@router.get("/{environment_id}", response_model=EnvironmentRead)
def read_one(environment: OwnedEnvironment) -> Environment:
    return environment


@router.patch("/{environment_id}", response_model=EnvironmentRead)
def update(
    payload: EnvironmentUpdate, environment: OwnedEnvironment, db: DbSession
) -> Environment:
    try:
        return update_environment(db, environment, payload)
    except EnvironmentNameTakenError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, NAME_TAKEN_DETAIL) from error


@router.delete("/{environment_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove(environment: OwnedEnvironment, db: DbSession) -> Response:
    delete_environment(db, environment)
    return Response(status_code=status.HTTP_204_NO_CONTENT)