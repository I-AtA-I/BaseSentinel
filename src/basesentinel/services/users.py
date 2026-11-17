
import re

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from basesentinel import db
from basesentinel.core.security import hash_password, verify_password
from basesentinel.models import User
from basesentinel.models.base import utcnow_naive


class UserAlreadyExistsError(Exception):
    pass


class UserService:
    VALID_ROLES = {"admin", "analyst", "viewer"}

    @staticmethod
    def normalize_username(username: str) -> str:
        if not isinstance(username, str):
            raise ValueError("Invalid username.")

        normalized = username.strip().lower()

        if not re.fullmatch(r"[a-z0-9._-]{3,64}", normalized):
            raise ValueError("Username must contain 3-64 valid characters.")

        return normalized

    @staticmethod
    def validate_password(password: str) -> None:
        if not isinstance(password, str):
            raise ValueError("Invalid password.")

        if len(password) < 12:
            raise ValueError("Password must contain at least 12 characters.")

        if len(password) > 1024:
            raise ValueError("Password is too long.")

    @classmethod
    def create_user(
        cls,
        username: str,
        password: str,
        role: str = "viewer",
    ) -> User:
        normalized_username = cls.normalize_username(username)
        cls.validate_password(password)

        if role not in cls.VALID_ROLES:
            raise ValueError("Invalid user role.")

        existing_user = db.session.scalar(
            select(User.id).where(
                User.username == normalized_username
            )
        )

        if existing_user is not None:
            raise UserAlreadyExistsError("Username is unavailable.")

        user = User(
            username=normalized_username,
            password_hash=hash_password(password),
            role=role,
            is_active=True,
        )

        db.session.add(user)

        try:
            db.session.commit()
        except IntegrityError as exc:
            db.session.rollback()
            raise UserAlreadyExistsError(
                "Username is unavailable."
            ) from exc

        return user

    @classmethod
    def authenticate(
        cls,
        username: str,
        password: str,
    ) -> User | None:
        try:
            normalized_username = cls.normalize_username(username)
        except ValueError:
            return None

        if not isinstance(password, str):
            return None

        user = db.session.scalar(
            select(User).where(
                User.username == normalized_username
            )
        )

        if user is None or not user.is_active:
            return None

        if not verify_password(password, user.password_hash):
            return None

        user.last_login_at = utcnow_naive()
        db.session.commit()

        return user
