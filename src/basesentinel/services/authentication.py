
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import joinedload

from basesentinel import db
from basesentinel.core.security import hash_agent_token
from basesentinel.models import Agent, AgentCredential
from basesentinel.models.base import utcnow_naive


@dataclass(frozen=True)
class AuthenticatedAgent:
    agent: Agent
    credential: AgentCredential


class AgentAuthenticationService:
    ACTIVITY_UPDATE_INTERVAL = timedelta(seconds=60)
    MAX_TOKEN_LENGTH = 256

    @classmethod
    def authenticate(cls, token: str) -> AuthenticatedAgent | None:
        """Authenticate an agent using its bearer token."""

        if not isinstance(token, str):
            return None

        if len(token) > cls.MAX_TOKEN_LENGTH:
            return None

        try:
            token_hash = hash_agent_token(token)
        except ValueError:
            return None

        credential = db.session.scalar(
            select(AgentCredential)
            .options(joinedload(AgentCredential.agent))
            .where(AgentCredential.secret_hash == token_hash)
        )

        if credential is None:
            return None

        agent = credential.agent

        if agent is None:
            return None

        now = utcnow_naive()

        if (
            credential.revoked_at is not None
            or credential.expires_at <= now
        ):
            return None

        if (
            agent.status != "active"
            or agent.revoked_at is not None
            or agent.uninstalled_at is not None
        ):
            return None

        update_threshold = now - cls.ACTIVITY_UPDATE_INTERVAL

        credential_needs_update = (
            credential.last_used_at is None
            or credential.last_used_at <= update_threshold
        )

        agent_needs_update = (
            agent.last_checkin_at is None
            or agent.last_checkin_at <= update_threshold
        )

        if credential_needs_update or agent_needs_update:
            credential.last_used_at = now
            agent.last_checkin_at = now

            db.session.commit()

            # Refresh objects after commit because SQLAlchemy
            # expires ORM objects by default.
            db.session.refresh(credential)
            db.session.refresh(agent)

        return AuthenticatedAgent(
            agent=agent,
            credential=credential,
        )
