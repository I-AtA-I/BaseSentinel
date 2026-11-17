
from dataclasses import dataclass

from sqlalchemy import select

from basesentinel import db
from basesentinel.models import Alert, User
from basesentinel.models.base import utcnow_naive


class AlertNotFoundError(Exception):
    pass


class AlertTransitionConflictError(Exception):
    pass


@dataclass(frozen=True)
class AlertTransitionResult:
    alert: Alert
    changed: bool


class AlertService:
    ALLOWED_ROLES = {"admin", "analyst"}

    @staticmethod
    def _lock_operator(user_id) -> User:
        user = db.session.scalar(
            select(User)
            .where(User.id == user_id)
            .with_for_update()
        )

        if (
            user is None
            or not user.is_active
            or user.role not in AlertService.ALLOWED_ROLES
        ):
            raise PermissionError(
                "Administrator or analyst access is required."
            )

        return user

    @classmethod
    def acknowledge(
        cls,
        alert_id,
        user_id,
    ) -> AlertTransitionResult:
        """Acknowledge an open alert."""

        session = db.session

        try:
            user = cls._lock_operator(user_id)

            alert = session.scalar(
                select(Alert)
                .where(Alert.id == alert_id)
                .with_for_update()
            )

            if alert is None:
                raise AlertNotFoundError("Alert not found.")

            if alert.status == "resolved":
                raise AlertTransitionConflictError(
                    "Resolved alerts cannot be acknowledged."
                )

            if alert.status == "acknowledged":
                session.commit()
                session.refresh(alert)

                return AlertTransitionResult(
                    alert=alert,
                    changed=False,
                )

            now = utcnow_naive()

            alert.status = "acknowledged"
            alert.acknowledged_by_user_id = user.id
            alert.acknowledged_at = now
            alert.updated_at = now

            session.commit()
            session.refresh(alert)

            return AlertTransitionResult(
                alert=alert,
                changed=True,
            )

        except Exception:
            session.rollback()
            raise

    @classmethod
    def resolve(
        cls,
        alert_id,
        user_id,
    ) -> AlertTransitionResult:
        """Resolve an open or acknowledged alert."""

        session = db.session

        try:
            cls._lock_operator(user_id)

            alert = session.scalar(
                select(Alert)
                .where(Alert.id == alert_id)
                .with_for_update()
            )

            if alert is None:
                raise AlertNotFoundError("Alert not found.")

            if alert.status == "resolved":
                session.commit()
                session.refresh(alert)

                return AlertTransitionResult(
                    alert=alert,
                    changed=False,
                )

            now = utcnow_naive()

            alert.status = "resolved"
            alert.resolved_at = now
            alert.updated_at = now

            session.commit()
            session.refresh(alert)

            return AlertTransitionResult(
                alert=alert,
                changed=True,
            )

        except Exception:
            session.rollback()
            raise
