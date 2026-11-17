import hashlib
import hmac
import secrets
import uuid
from datetime import timedelta

from flask import current_app
from sqlalchemy import select

from basesentinel import db
from basesentinel.core.security import (
    generate_pairing_code,
    hash_pairing_code,
    hash_password,
    verify_password,
)
from basesentinel.models import PairingCode, ServerSettings, User
from basesentinel.models.base import utcnow_naive
from basesentinel.services.enrollment import EnrollmentService


class ServerAccessError(Exception):
    pass


class ServerEnrollmentService:
    @staticmethod
    def _pepper():
        pepper = current_app.config.get("PAIRING_CODE_PEPPER")
        if not isinstance(pepper, str) or len(pepper.encode("utf-8")) < 32:
            raise RuntimeError("Server enrollment secret is not configured.")
        return pepper.encode("utf-8")

    @classmethod
    def _hash_secret(cls, secret):
        if not isinstance(secret, str) or not 32 <= len(secret) <= 256:
            raise ValueError("Invalid server access code.")
        return hmac.new(cls._pepper(), secret.encode("utf-8"), hashlib.sha256).hexdigest()

    @classmethod
    def get_or_create_settings(cls):
        settings = db.session.get(ServerSettings, 1)
        if settings is not None:
            return settings, None
        secret = secrets.token_urlsafe(32)
        settings = ServerSettings(
            id=1,
            server_id=str(uuid.uuid4()),
            server_secret_hash=cls._hash_secret(secret),
            enrollment_mode="automatic",
        )
        db.session.add(settings)
        db.session.commit()
        return settings, secret

    @classmethod
    def rotate_secret(cls):
        settings, _ = cls.get_or_create_settings()
        secret = secrets.token_urlsafe(32)
        settings.server_secret_hash = cls._hash_secret(secret)
        settings.updated_at = utcnow_naive()
        db.session.commit()
        return settings, secret

    @classmethod
    def update_settings(cls, mode, connection_password=None):
        if mode not in {"automatic", "approval_required", "disabled"}:
            raise ValueError("Enrollment mode must be automatic, approval_required, or disabled.")
        if connection_password is not None:
            if not isinstance(connection_password, str) or len(connection_password) > 256:
                raise ValueError("Connection password is too long.")
            connection_password = connection_password.strip() or None
        settings, _ = cls.get_or_create_settings()
        settings.enrollment_mode = mode
        settings.connection_password_hash = (
            hash_password(connection_password) if connection_password else None
        )
        settings.updated_at = utcnow_naive()
        db.session.commit()
        return settings

    @classmethod
    def enroll(cls, server_id, server_secret, connection_password, hostname,
               platform, agent_version, platform_version=None, architecture=None):
        settings = db.session.get(ServerSettings, 1)
        if settings is None or settings.enrollment_mode != "automatic":
            raise ServerAccessError("New agent enrollment is disabled.")
        if not isinstance(server_id, str) or not hmac.compare_digest(server_id, settings.server_id):
            raise ServerAccessError("Server access details are invalid.")
        try:
            candidate = cls._hash_secret(server_secret)
        except (ValueError, TypeError):
            raise ServerAccessError("Server access details are invalid.") from None
        if not hmac.compare_digest(candidate, settings.server_secret_hash):
            raise ServerAccessError("Server access details are invalid.")
        stored_password = settings.connection_password_hash
        if stored_password:
            if not isinstance(connection_password, str) or not verify_password(connection_password, stored_password):
                raise ServerAccessError("Server access details are invalid.")
        elif connection_password not in (None, ""):
            raise ServerAccessError("Server access details are invalid.")

        admin = db.session.scalar(
            select(User)
            .where(User.role == "admin", User.is_active.is_(True))
            .order_by(User.created_at)
            .limit(1)
        )
        if admin is None:
            raise RuntimeError("No active administrator is available for agent enrollment.")
        code = generate_pairing_code()
        pepper = current_app.config.get("PAIRING_CODE_PEPPER")
        now = utcnow_naive()
        pairing = PairingCode(
            code_hash=hash_pairing_code(code, pepper),
            created_by_user_id=admin.id,
            created_at=now,
            expires_at=now + timedelta(minutes=2),
        )
        db.session.add(pairing)
        db.session.commit()
        try:
            return EnrollmentService.enroll(
                pairing_code=code,
                hostname=hostname,
                platform=platform,
                agent_version=agent_version,
                platform_version=platform_version,
                architecture=architecture,
            )
        except Exception:
            db.session.rollback()
            raise
