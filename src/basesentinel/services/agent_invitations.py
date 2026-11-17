import hashlib
import hmac
import secrets
from datetime import timedelta

from flask import current_app
from sqlalchemy import select

from basesentinel import db
from basesentinel.core.security import generate_pairing_code, hash_pairing_code
from basesentinel.models import AgentEnrollmentRequest, AgentInvitation, PairingCode, ServerSettings, User
from basesentinel.models.base import utcnow_naive
from basesentinel.services.enrollment import EnrollmentService


class InvalidInvitationError(Exception):
    pass


class EnrollmentPending(Exception):
    def __init__(self, request_id):
        self.request_id = str(request_id)
        super().__init__("Enrollment is waiting for administrator approval.")


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
    def _hash_code(cls, code):
        if not isinstance(code, str):
            raise InvalidInvitationError()
        normalized = code.replace("-", "").replace(" ", "").upper()
        if len(normalized) != 16 or any(char not in "23456789ABCDEFGHJKMNPQRSTVWXYZ" for char in normalized):
            raise InvalidInvitationError()
        return hmac.new(cls._pepper(), normalized.encode("ascii"), hashlib.sha256).hexdigest()

    @classmethod
    def create(cls, created_by_user_id, ttl):
        if not isinstance(ttl, timedelta) or not cls.MIN_TTL <= ttl <= cls.MAX_TTL:
            raise ValueError("Invitation lifetime must be between 5 minutes and 24 hours.")

        user = db.session.get(User, created_by_user_id)
        if user is None or not user.is_active or user.role != "admin":
            raise PermissionError("Administrator access is required.")
        settings = db.session.get(ServerSettings, 1)
        if settings is None or settings.enrollment_mode not in {"automatic", "approval_required"}:
            raise RuntimeError("New agent enrollment is disabled.")

        token = secrets.token_urlsafe(32)
        alphabet = "23456789ABCDEFGHJKMNPQRSTVWXYZ"
        raw_code = "".join(secrets.choice(alphabet) for _ in range(16))
        invitation_code = "-".join(raw_code[index:index + 4] for index in range(0, 16, 4))
        record = AgentInvitation(
            token_hash=cls._hash_token(token),
            code_hash=cls._hash_code(invitation_code),
            created_by_user_id=user.id,
            created_at=utcnow_naive(),
            expires_at=utcnow_naive() + ttl,
        )
        db.session.add(record)
        db.session.commit()
        return record, token, invitation_code

    @classmethod
    def list_requests(cls, status="pending", limit=100):
        query = select(AgentEnrollmentRequest).order_by(
            AgentEnrollmentRequest.requested_at.desc()
        ).limit(limit)
        if status:
            query = query.where(AgentEnrollmentRequest.status == status)
        return db.session.scalars(query).all()

    @classmethod
    def review_request(cls, request_id, reviewer_id, decision):
        if decision not in {"approved", "rejected"}:
            raise ValueError("Invalid enrollment decision.")
        record = db.session.scalar(
            select(AgentEnrollmentRequest)
            .where(AgentEnrollmentRequest.id == request_id)
            .with_for_update()
        )
        if record is None:
            return None
        if record.status != "pending":
            return False
        invitation = db.session.get(AgentInvitation, record.invitation_id)
        if invitation is None or invitation.expires_at <= utcnow_naive() or invitation.revoked_at is not None:
            record.status = "expired"
        else:
            record.status = decision
        record.reviewed_by_user_id = reviewer_id
        record.reviewed_at = utcnow_naive()
        db.session.commit()
        return record.status == decision

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
    def enroll(cls, token, hostname, platform, agent_version, platform_version=None, architecture=None, invitation_code=None):
        # Validate metadata before consuming the one-time invitation.
        hostname = EnrollmentService._validate_text(hostname, "hostname", 255, required=True)
        platform = EnrollmentService._validate_text(platform, "platform", 24, required=True).lower()
        agent_version = EnrollmentService._validate_text(agent_version, "agent version", 40, required=True)
        platform_version = EnrollmentService._validate_text(platform_version, "platform version", 80)
        architecture = EnrollmentService._validate_text(architecture, "architecture", 32)

        if platform not in {"windows", "linux"}:
            raise ValueError("Unsupported platform.")

        settings = db.session.get(ServerSettings, 1)
        if settings is None or settings.enrollment_mode not in {"automatic", "approval_required"}:
            raise InvalidInvitationError()

        if token:
            credential_filter = AgentInvitation.token_hash == cls._hash_token(token)
        elif invitation_code:
            credential_filter = AgentInvitation.code_hash == cls._hash_code(invitation_code)
        else:
            raise InvalidInvitationError()
        now = utcnow_naive()
        invitation = db.session.scalar(
            select(AgentInvitation)
            .where(credential_filter)
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

        enrollment_request = db.session.scalar(
            select(AgentEnrollmentRequest)
            .where(AgentEnrollmentRequest.invitation_id == invitation.id)
            .with_for_update()
        )
        if settings.enrollment_mode == "approval_required":
            if enrollment_request is None:
                enrollment_request = AgentEnrollmentRequest(
                    invitation_id=invitation.id,
                    hostname=hostname,
                    platform=platform,
                    agent_version=agent_version,
                    platform_version=platform_version,
                    architecture=architecture,
                    status="pending",
                    requested_at=now,
                )
                db.session.add(enrollment_request)
                db.session.commit()
                raise EnrollmentPending(enrollment_request.id)
            if enrollment_request.status == "pending":
                raise EnrollmentPending(enrollment_request.id)
            if enrollment_request.status != "approved":
                raise InvalidInvitationError()
            if (
                enrollment_request.hostname != hostname
                or enrollment_request.platform != platform
                or enrollment_request.agent_version != agent_version
            ):
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
            result = EnrollmentService.enroll(
                pairing_code=code,
                hostname=hostname,
                platform=platform,
                agent_version=agent_version,
                platform_version=platform_version,
                architecture=architecture,
            )
            if enrollment_request is not None:
                enrollment_request.status = "completed"
                db.session.commit()
            return result
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
