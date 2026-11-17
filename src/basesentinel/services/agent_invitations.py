import hashlib
import hmac
import secrets
from datetime import timedelta

from flask import current_app
from sqlalchemy import select

from basesentinel import db
from basesentinel.core.security import generate_pairing_code, hash_pairing_code
from basesentinel.models import AgentInvitation, PairingCode, ServerSettings, User
from basesentinel.models.base import utcnow_naive
from basesentinel.services.enrollment import EnrollmentService


class InvalidInvitationError(Exception):
    pass


class AgentInvitationService:
    MIN_TTL = timedelta(minutes=5)
    MAX_TTL = timedelta(hours=24)

    @staticmethod
    def _pepper():
        pepper = current_app.config.get("PAIRING_CODE_PEPPER")
        if not isinstance(pepper, str) or len(pepper.encode("utf-8")) < 32:
            raise RuntimeError("Invitation token secret is not configured.")
        return pepper.encode("utf-8")

    @classmethod
    def _hash_token(cls, token):
        if not isinstance(token, str) or not 32 <= len(token) <= 256:
            raise InvalidInvitationError()
        return hmac.new(cls._pepper(), token.encode("utf-8"), hashlib.sha256).hexdigest()

    @classmethod
    def create(cls, created_by_user_id, ttl):
        if not isinstance(ttl, timedelta) or not cls.MIN_TTL <= ttl <= cls.MAX_TTL:
            raise ValueError("Invitation lifetime must be between 5 minutes and 24 hours.")

        user = db.session.get(User, created_by_user_id)
        if user is None or not user.is_active or user.role != "admin":
            raise PermissionError("Administrator access is required.")

        token = secrets.token_urlsafe(32)
        record = AgentInvitation(
            token_hash=cls._hash_token(token),
            created_by_user_id=user.id,
            created_at=utcnow_naive(),
            expires_at=utcnow_naive() + ttl,
        )
        db.session.add(record)
        db.session.commit()
        return record, token

    @classmethod
    def list_recent(cls, limit=20):
        return db.session.scalars(
            select(AgentInvitation)
            .order_by(AgentInvitation.created_at.desc())
            .limit(limit)
        ).all()

    @classmethod
    def revoke(cls, invitation_id):
        record = db.session.scalar(
            select(AgentInvitation)
            .where(AgentInvitation.id == invitation_id)
            .with_for_update()
        )
        if record is None:
            return None
        now = utcnow_naive()
        if record.consumed_at is None and record.revoked_at is None and record.expires_at > now:
            record.revoked_at = now
            db.session.commit()
            return True
        return False

    @classmethod
    def enroll(cls, token, hostname, platform, agent_version, platform_version=None, architecture=None):
        # Validate metadata before consuming the one-time invitation.
        hostname = EnrollmentService._validate_text(hostname, "hostname", 255, required=True)
        platform = EnrollmentService._validate_text(platform, "platform", 24, required=True).lower()
        agent_version = EnrollmentService._validate_text(agent_version, "agent version", 40, required=True)
        platform_version = EnrollmentService._validate_text(platform_version, "platform version", 80)
        architecture = EnrollmentService._validate_text(architecture, "architecture", 32)

        if platform not in {"windows", "linux"}:
            raise ValueError("Unsupported platform.")

        settings = db.session.get(ServerSettings, 1)
        if settings is None or settings.enrollment_mode != "automatic":
            raise InvalidInvitationError()

        token_hash = cls._hash_token(token)
        now = utcnow_naive()
        invitation = db.session.scalar(
            select(AgentInvitation)
            .where(AgentInvitation.token_hash == token_hash)
            .with_for_update()
        )
        if (
            invitation is None
            or invitation.consumed_at is not None
            or invitation.revoked_at is not None
            or invitation.expires_at <= now
        ):
            raise InvalidInvitationError()

        creator = db.session.get(User, invitation.created_by_user_id)
        if creator is None or not creator.is_active or creator.role != "admin":
            raise InvalidInvitationError()

        code = generate_pairing_code()
        pepper = current_app.config.get("PAIRING_CODE_PEPPER")
        pairing = PairingCode(
            code_hash=hash_pairing_code(code, pepper),
            created_by_user_id=creator.id,
            created_at=now,
            expires_at=now + timedelta(minutes=2),
        )
        db.session.add(pairing)
        invitation.consumed_at = now
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
            # The invitation remains consumed. Revoke its temporary pairing
            # record so a failed attempt cannot leave another enrollment path.
            stale_pairing = db.session.scalar(
                select(PairingCode).where(PairingCode.code_hash == hash_pairing_code(code, pepper))
            )
            if stale_pairing is not None and stale_pairing.consumed_at is None:
                stale_pairing.revoked_at = utcnow_naive()
                db.session.commit()
            raise
