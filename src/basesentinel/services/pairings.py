
from datetime import timedelta

from flask import current_app
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from basesentinel import db
from basesentinel.core.security import (
    generate_pairing_code,
    hash_pairing_code,
)
from basesentinel.models import Asset, PairingCode, User
from basesentinel.models.base import utcnow_naive


class PairingService:
    DEFAULT_TTL = timedelta(minutes=10)
    MAX_TTL = timedelta(minutes=30)
    CODE_GENERATION_ATTEMPTS = 5

    @staticmethod
    def _get_pepper() -> str:
        pepper = current_app.config.get("PAIRING_CODE_PEPPER")

        if not isinstance(pepper, str) or len(pepper.encode("utf-8")) < 32:
            raise RuntimeError("Pairing code secret is not configured.")

        return pepper

    @staticmethod
    def _require_admin(user_id) -> User:
        user = db.session.get(User, user_id)

        if user is None or not user.is_active or user.role != "admin":
            raise PermissionError("Administrator access is required.")

        return user

    @classmethod
    def create_code(
        cls,
        created_by_user_id,
        target_asset_id=None,
        ttl: timedelta = DEFAULT_TTL,
    ) -> tuple[PairingCode, str]:
        """Create a pairing code and return its record and plaintext value."""

        if not isinstance(ttl, timedelta):
            raise ValueError("Invalid pairing code lifetime.")

        if ttl <= timedelta(0) or ttl > cls.MAX_TTL:
            raise ValueError("Pairing code lifetime must be between 0 and 30 minutes.")

        cls._require_admin(created_by_user_id)

        if target_asset_id is not None:
            asset = db.session.get(Asset, target_asset_id)

            if asset is None:
                raise ValueError("Target asset does not exist.")

        pepper = cls._get_pepper()
        now = utcnow_naive()

        for _ in range(cls.CODE_GENERATION_ATTEMPTS):
            raw_code = generate_pairing_code()
            code_hash = hash_pairing_code(raw_code, pepper)

            existing = db.session.scalar(
                select(PairingCode.id).where(
                    PairingCode.code_hash == code_hash
                )
            )

            if existing is not None:
                continue

            pairing_code = PairingCode(
                code_hash=code_hash,
                created_by_user_id=created_by_user_id,
                target_asset_id=target_asset_id,
                created_at=now,
                expires_at=now + ttl,
            )

            db.session.add(pairing_code)

            try:
                db.session.commit()
            except IntegrityError as exc:
                db.session.rollback()
                raise RuntimeError(
                    "Could not create a unique pairing code."
                ) from exc

            return pairing_code, raw_code

        raise RuntimeError("Could not generate a unique pairing code.")

    @classmethod
    def revoke_code(cls, pairing_code_id, revoked_by_user_id) -> bool:
        """Revoke an unused pairing code."""

        cls._require_admin(revoked_by_user_id)

        pairing_code = db.session.scalar(
            select(PairingCode)
            .where(PairingCode.id == pairing_code_id)
            .with_for_update()
        )

        if pairing_code is None:
            return False

        now = utcnow_naive()

        if (
            pairing_code.consumed_at is not None
            or pairing_code.revoked_at is not None
            or pairing_code.expires_at <= now
        ):
            return False

        pairing_code.revoked_at = now

        db.session.commit()

        return True
