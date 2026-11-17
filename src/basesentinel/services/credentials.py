
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select

from basesentinel import db
from basesentinel.core.security import (
    generate_agent_token,
    hash_agent_token,
)
from basesentinel.models import Agent, AgentCredential, User
from basesentinel.models.base import utcnow_naive


class InvalidAgentCredentialError(Exception):
    pass


class AgentUnavailableError(Exception):
    pass


@dataclass(frozen=True)
class RotatedCredential:
    credential: AgentCredential
    token: str


class AgentCredentialService:
    DEFAULT_TTL = timedelta(days=90)
    MAX_TTL = timedelta(days=365)
    MAX_TOKEN_LENGTH = 256

    @classmethod
    def _validate_ttl(cls, ttl: timedelta) -> None:
        if not isinstance(ttl, timedelta):
            raise ValueError("Invalid credential lifetime.")

        if ttl <= timedelta(0) or ttl > cls.MAX_TTL:
            raise ValueError(
                "Credential lifetime must be between 0 and 365 days."
            )

    @classmethod
    def _get_token_hash(cls, token: str) -> str:
        if (
            not isinstance(token, str)
            or len(token) < 32
            or len(token) > cls.MAX_TOKEN_LENGTH
        ):
            raise InvalidAgentCredentialError(
                "Credential is invalid or unavailable."
            )

        try:
            return hash_agent_token(token)
        except ValueError as exc:
            raise InvalidAgentCredentialError(
                "Credential is invalid or unavailable."
            ) from exc

    @staticmethod
    def _require_admin(admin_user_id) -> User:
        admin = db.session.scalar(
            select(User)
            .where(User.id == admin_user_id)
            .with_for_update()
        )

        if admin is None or not admin.is_active or admin.role != "admin":
            db.session.rollback()
            raise PermissionError("Administrator access is required.")

        return admin

    @classmethod
    def _lock_current_credential(
        cls,
        token_hash: str,
    ) -> tuple[Agent, AgentCredential, object]:
        session = db.session

        # Find the agent ID before acquiring row locks.
        candidate = session.execute(
            select(
                AgentCredential.id,
                AgentCredential.agent_id,
            ).where(
                AgentCredential.secret_hash == token_hash
            )
        ).one_or_none()

        if candidate is None:
            raise InvalidAgentCredentialError(
                "Credential is invalid or unavailable."
            )

        # Always lock the agent before its credentials.
        agent = session.scalar(
            select(Agent)
            .where(Agent.id == candidate.agent_id)
            .with_for_update()
        )

        if agent is None:
            raise InvalidAgentCredentialError(
                "Credential is invalid or unavailable."
            )

        credential = session.scalar(
            select(AgentCredential)
            .where(
                AgentCredential.id == candidate.id,
                AgentCredential.agent_id == agent.id,
                AgentCredential.secret_hash == token_hash,
            )
            .with_for_update()
        )

        if credential is None:
            raise InvalidAgentCredentialError(
                "Credential is invalid or unavailable."
            )

        now = utcnow_naive()

        if (
            credential.revoked_at is not None
            or credential.expires_at <= now
            or agent.status != "active"
            or agent.revoked_at is not None
            or agent.uninstalled_at is not None
        ):
            raise InvalidAgentCredentialError(
                "Credential is invalid or unavailable."
            )

        return agent, credential, now

    @classmethod
    def rotate_credential(
        cls,
        token: str,
        ttl: timedelta = DEFAULT_TTL,
    ) -> RotatedCredential:
        """Replace an active credential with a new one."""

        cls._validate_ttl(ttl)
        token_hash = cls._get_token_hash(token)

        session = db.session

        try:
            agent, old_credential, now = cls._lock_current_credential(
                token_hash
            )

            new_token = generate_agent_token()

            new_credential = AgentCredential(
                agent_id=agent.id,
                secret_hash=hash_agent_token(new_token),
                created_at=now,
                expires_at=now + ttl,
            )

            old_credential.revoked_at = now
            old_credential.last_used_at = now

            session.add(new_credential)
            session.flush()
            session.commit()
            session.refresh(new_credential)

            return RotatedCredential(
                credential=new_credential,
                token=new_token,
            )

        except Exception:
            session.rollback()
            raise

    @classmethod
    def revoke_credential(
        cls,
        credential_id,
        admin_user_id,
    ) -> bool:
        """Revoke one credential without revoking the whole agent."""

        session = db.session

        try:
            cls._require_admin(admin_user_id)

            candidate = session.execute(
                select(AgentCredential.agent_id).where(
                    AgentCredential.id == credential_id
                )
            ).one_or_none()

            if candidate is None:
                session.rollback()
                return False

            agent = session.scalar(
                select(Agent)
                .where(Agent.id == candidate.agent_id)
                .with_for_update()
            )

            if agent is None:
                session.rollback()
                return False

            credential = session.scalar(
                select(AgentCredential)
                .where(
                    AgentCredential.id == credential_id,
                    AgentCredential.agent_id == agent.id,
                )
                .with_for_update()
            )

            if credential is None or credential.revoked_at is not None:
                session.rollback()
                return False

            credential.revoked_at = utcnow_naive()

            session.commit()
            return True

        except Exception:
            session.rollback()
            raise

    @classmethod
    def revoke_agent(
        cls,
        agent_id,
        admin_user_id,
    ) -> bool:
        """Revoke an agent and all credentials belonging to it."""

        session = db.session

        try:
            cls._require_admin(admin_user_id)

            agent = session.scalar(
                select(Agent)
                .where(Agent.id == agent_id)
                .with_for_update()
            )

            if agent is None:
                session.rollback()
                return False

            credentials = session.scalars(
                select(AgentCredential)
                .where(AgentCredential.agent_id == agent.id)
                .with_for_update()
            ).all()

            now = utcnow_naive()

            changed = (
                agent.status != "revoked"
                or agent.revoked_at is None
            )

            agent.status = "revoked"

            if agent.revoked_at is None:
                agent.revoked_at = now

            agent.updated_at = now

            for credential in credentials:
                if credential.revoked_at is None:
                    credential.revoked_at = now
                    changed = True

            if not changed:
                session.rollback()
                return False

            session.commit()
            return True

        except Exception:
            session.rollback()
            raise

    @classmethod
    def rotate_agent_credential(
        cls,
        agent_id,
        admin_user_id,
        ttl: timedelta = DEFAULT_TTL,
    ) -> RotatedCredential | None:
        """Rotate all credentials for an agent as an administrator."""

        cls._validate_ttl(ttl)

        session = db.session

        try:
            # Lock the administrator first.
            cls._require_admin(admin_user_id)

            # Then lock the agent.
            agent = session.scalar(
                select(Agent)
                .where(Agent.id == agent_id)
                .with_for_update()
            )

            if agent is None:
                session.rollback()
                return None

            if (
                agent.status != "active"
                or agent.revoked_at is not None
                or agent.uninstalled_at is not None
            ):
                raise AgentUnavailableError(
                    "Agent is not active."
                )

            # Lock all credentials belonging to the agent.
            credentials = session.scalars(
                select(AgentCredential)
                .where(AgentCredential.agent_id == agent.id)
                .with_for_update()
            ).all()

            now = utcnow_naive()

            # Revoke all previously issued credentials.
            for credential in credentials:
                if credential.revoked_at is None:
                    credential.revoked_at = now

            token = generate_agent_token()

            new_credential = AgentCredential(
                agent_id=agent.id,
                secret_hash=hash_agent_token(token),
                created_at=now,
                expires_at=now + ttl,
            )

            session.add(new_credential)
            session.flush()
            session.commit()
            session.refresh(new_credential)

            return RotatedCredential(
                credential=new_credential,
                token=token,
            )

        except Exception:
            session.rollback()
            raise
