import uuid
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import InvalidTokenError, decode_access_token
from app.db.session import get_db
from app.models import Environment, User

bearer_scheme = HTTPBearer(auto_error=False)

DbSession = Annotated[Session, Depends(get_db)]


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: DbSession,
) -> User:
    if credentials is None:
        raise _unauthorized()
    try:
        user_id = decode_access_token(credentials.credentials)
    except InvalidTokenError as error:
        raise _unauthorized() from error
    user = db.get(User, user_id)
    if user is None:
        raise _unauthorized()
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def get_owned_environment(
    environment_id: uuid.UUID, user: CurrentUser, db: DbSession
) -> Environment:
    environment = db.scalar(
        select(Environment).where(
            Environment.id == environment_id, Environment.owner_id == user.id
        )
    )
    if environment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Environment not found")
    return environment


OwnedEnvironment = Annotated[Environment, Depends(get_owned_environment)]