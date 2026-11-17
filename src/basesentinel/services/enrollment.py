
from dataclasses import dataclass
from datetime import timedelta

from flask import current_app
from sqlalchemy import select

from basesentinel import db
from basesentinel.core.security import (
    generate_agent_token,
    hash_agent_token,
    hash_pairing_code,
)
from basesentinel.models import (
    Agent,
    AgentCredential,
    Asset,
    PairingCode,
)
from basesentinel.models.base import utcnow_naive


class EnrollmentError(Exception):
    pass


class InvalidPairingCodeError(EnrollmentError):
    pass


class AssetAlreadyEnrolledError(EnrollmentError):
    pass


@dataclass(frozen=True)
class EnrollmentResult:
    asset: Asset
    agent: Agent
    credential: AgentCredential
    token: str


class EnrollmentService:
    DEFAULT_CREDENTIAL_TTL = timedelta(days=90)
    MAX_CREDENTIAL_TTL = timedelta(days=365)

    @staticmethod
    def _get_pepper() -> str:
        pepper = current_app.config.get("PAIRING_CODE_PEPPER")

        if not isinstance(pepper, str) or len(pepper.encode("utf-8")) < 32:
            raise RuntimeError("Pairing code secret is not configured.")

        return pepper

    @staticmethod
    def _validate_text(
        value: str,
        field: str,
        max_length: int,
        required: bool = False,
    ) -> str | None:
        if value is None and not required:
            return None

        if not isinstance(value, str):
            raise ValueError(f"Invalid {field}.")

        value = value.strip()

        if required and not value:
            raise ValueError(f"{field} is required.")

        if not value:
            return None

        if len(value) > max_length:
            raise ValueError(f"{field} is too long.")

        if any(ord(character) < 32 for character in value):
            raise ValueError(f"Invalid characters in {field}.")

        return value

    @classmethod
    def enroll(
        cls,
        pairing_code: str,
        hostname: str,
        platform: str,
        agent_version: str,
        platform_version: str | None = None,
        architecture: str | None = None,
        credential_ttl: timedelta = DEFAULT_CREDENTIAL_TTL,
    ) -> EnrollmentResult:
        hostname = cls._validate_text(
            hostname, "hostname", 255, required=True
        )

        platform = cls._validate_text(
            platform, "platform", 24, required=True
        ).lower()

        agent_version = cls._validate_text(
            agent_version, "agent version", 40, required=True
        )

        platform_version = cls._validate_text(
            platform_version, "platform version", 80
        )

        architecture = cls._validate_text(
            architecture, "architecture", 32
        )

        if platform not in {"windows", "linux"}:
            raise ValueError("Unsupported platform.")

        if not isinstance(credential_ttl, timedelta):
            raise ValueError("Invalid credential lifetime.")

        if (
            credential_ttl <= timedelta(0)
            or credential_ttl > cls.MAX_CREDENTIAL_TTL
        ):
            raise ValueError("Credential lifetime is outside allowed limits.")

        pepper = cls._get_pepper()
        code_hash = hash_pairing_code(pairing_code, pepper)

        session = db.session
        now = utcnow_naive()

        try:
            # Lock the pairing record to prevent concurrent enrollment.
            code_record = session.scalar(
                select(PairingCode)
                .where(PairingCode.code_hash == code_hash)
                .with_for_update()
            )

            if (
                code_record is None
                or code_record.consumed_at is not None
                or code_record.consumed_by_agent_id is not None
                or code_record.revoked_at is not None
                or code_record.expires_at <= now
            ):
                raise InvalidPairingCodeError(
                    "Pairing code is invalid or unavailable."
                )

            if code_record.target_asset_id is not None:
                # Lock the asset before checking existing installations.
                asset = session.scalar(
                    select(Asset)
                    .where(Asset.id == code_record.target_asset_id)
                    .with_for_update()
                )

                if asset is None or asset.lifecycle_state == "retired":
                    raise EnrollmentError(
                        "Target asset is unavailable."
                    )

                # The asset lock serializes enrollment for this asset.
                active_agent_id = session.scalar(
                    select(Agent.id)
                    .where(
                        Agent.asset_id == asset.id,
                        Agent.status == "active",
                    )
                    .with_for_update()
                )

                if active_agent_id is not None:
                    raise AssetAlreadyEnrolledError(
                        "Asset already has an active agent."
                    )

                asset.hostname = hostname
                asset.os_name = platform

                if platform_version is not None:
                    asset.os_version = platform_version

                asset.last_seen_at = now
                asset.updated_at = now

            else:
                asset = Asset(
                    display_name=hostname,
                    hostname=hostname,
                    asset_type="unknown",
                    os_name=platform,
                    os_version=platform_version,
                    first_seen_at=now,
                    last_seen_at=now,
                    created_at=now,
                    updated_at=now,
                )

                session.add(asset)
                session.flush()

            agent = Agent(
                asset_id=asset.id,
                platform=platform,
                platform_version=platform_version,
                architecture=architecture,
                agent_version=agent_version,
                status="active",
                enrolled_at=now,
                last_checkin_at=now,
                created_at=now,
                updated_at=now,
            )

            session.add(agent)
            session.flush()

            token = generate_agent_token()

            credential = AgentCredential(
                agent_id=agent.id,
                secret_hash=hash_agent_token(token),
                created_at=now,
                expires_at=now + credential_ttl,
            )

            session.add(credential)

            code_record.consumed_at = now
            code_record.consumed_by_agent_id = agent.id

            session.commit()

            return EnrollmentResult(
                asset=asset,
                agent=agent,
                credential=credential,
                token=token,
            )

        except Exception:
            session.rollback()
            raise
