
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select

from basesentinel import db
from basesentinel.core.security import (
    generate_user_session_token,
    hash_user_session_token,
)
from basesentinel.models import User, UserSession
from basesentinel.models.base import utcnow_naive


@dataclass(frozen=True)
class AuthenticatedUser:
    user: User
    session: UserSession


class UserSessionService:
    DEFAULT_TTL = timedelta(days=30)
    MAX_TTL = timedelta(days=90)
    ACTIVITY_UPDATE_INTERVAL = timedelta(seconds=60)

    @classmethod
    def _validate_ttl(cls, ttl):
        if not isinstance(ttl, timedelta):
            raise ValueError("Invalid session lifetime.")

        if ttl <= timedelta(0) or ttl > cls.MAX_TTL:
            raise ValueError(
                "Session lifetime must be between 0 and 90 days."
            )

    @staticmethod
    def _get_token_hash(token):
        try:
            return hash_user_session_token(token)
        except ValueError as exc:
            raise ValueError("Invalid session token.") from exc

    @classmethod
    def create_session(
        cls,
        user_id,
        ttl=DEFAULT_TTL,
    ):
        cls._validate_ttl(ttl)

        session = db.session

        try:
            user = session.scalar(
                select(User)
                .where(User.id == user_id)
                .with_for_update()
            )

            if user is None or not user.is_active:
                raise PermissionError("User is unavailable.")

            now = utcnow_naive()
            token = generate_user_session_token()

            user_session = UserSession(
                user_id=user.id,
                token_hash=hash_user_session_token(token),
                created_at=now,
                expires_at=now + ttl,
            )

            session.add(user_session)
            session.commit()
            session.refresh(user_session)

            return token, user_session

        except Exception:
            session.rollback()
            raise

    @classmethod
    def authenticate(cls, token):
        if (
            not isinstance(token, str)
            or len(token) < 32
            or len(token) > 256
        ):
            return None

        token_hash = cls._get_token_hash(token)
        session = db.session

        try:
            candidate = session.execute(
                select(
                    UserSession.id,
                    UserSession.user_id,
                ).where(
                    UserSession.token_hash == token_hash
                )
            ).one_or_none()

            if candidate is None:
                session.rollback()
                return None

            # Lock the user before locking the session.
            user = session.scalar(
                select(User)
                .where(User.id == candidate.user_id)
                .with_for_update()
            )

            if user is None:
                session.rollback()
                return None

            user_session = session.scalar(
                select(UserSession)
                .where(
                    UserSession.id == candidate.id,
                    UserSession.user_id == user.id,
                    UserSession.token_hash == token_hash,
                )
                .with_for_update()
            )

            if user_session is None:
                session.rollback()
                return None

            now = utcnow_naive()

            if (
                not user.is_active
                or user_session.revoked_at is not None
                or user_session.expires_at <= now
            ):
                session.rollback()
                return None

            if (
                user_session.last_used_at is None
                or now - user_session.last_used_at
                >= cls.ACTIVITY_UPDATE_INTERVAL
            ):
                user_session.last_used_at = now
                session.commit()

            return AuthenticatedUser(
                user=user,
                session=user_session,
            )

        except Exception:
            session.rollback()
            raise

    @classmethod
    def revoke_session(cls, token):
        if (
            not isinstance(token, str)
            or len(token) < 32
            or len(token) > 256
        ):
            return False

        token_hash = cls._get_token_hash(token)
        session = db.session

        try:
            candidate = session.execute(
                select(
                    UserSession.id,
                    UserSession.user_id,
                ).where(
                    UserSession.token_hash == token_hash
                )
            ).one_or_none()

            if candidate is None:
                session.rollback()
                return False

            user = session.scalar(
                select(User)
                .where(User.id == candidate.user_id)
                .with_for_update()
            )

            if user is None:
                session.rollback()
                return False

            user_session = session.scalar(
                select(UserSession)
                .where(
                    UserSession.id == candidate.id,
                    UserSession.user_id == user.id,
                    UserSession.token_hash == token_hash,
                )
                .with_for_update()
            )

            if (
                user_session is None
                or user_session.revoked_at is not None
            ):
                session.rollback()
                return False

            user_session.revoked_at = utcnow_naive()
            session.commit()

            return True

        except Exception:
            session.rollback()
            raise
