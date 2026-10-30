from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import TIMING_EQUALIZER_HASH, hash_password, verify_password
from app.models import User


class EmailAlreadyRegisteredError(Exception):
    pass


def register_user(db: Session, email: str, password: str) -> User:
    user = User(email=email, password_hash=hash_password(password))
    db.add(user)
    try:
        db.commit()
    except IntegrityError as error:
        db.rollback()
        raise EmailAlreadyRegisteredError(email) from error
    db.refresh(user)
    return user


def authenticate_user(db: Session, email: str, password: str) -> User | None:
    user = db.scalar(select(User).where(User.email == email))
    if user is None:
        verify_password(password, TIMING_EQUALIZER_HASH)
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user