
import hashlib

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from basesentinel import db
from basesentinel.models import Agent, Alert, SecurityEvent
from basesentinel.models.base import utcnow_naive


class DetectionService:
    HIGH_SEVERITY_RULE = "high_severity_event"
    REPEATED_FAILED_LOGINS_RULE = "repeated_failed_logins"

    HIGH_SEVERITY_THRESHOLD = 9
    FAILED_LOGIN_THRESHOLD = 5
    FAILED_LOGIN_WINDOW = timedelta(minutes=5)

    @staticmethod
    def _fingerprint(value: str) -> str:
        return hashlib.sha256(
            value.encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _lock_agent(agent_id):
        return db.session.scalar(
            select(Agent)
            .where(Agent.id == agent_id)
            .with_for_update()
        )

    @classmethod
    def process_event(cls, event: SecurityEvent) -> list[Alert]:
        """
        Evaluate one persisted event against all detection rules.

        This method does not commit. The caller owns the transaction.
        """

        if event.id is None:
            raise ValueError("Event must be persisted before detection.")

        session = db.session

        try:
            agent = cls._lock_agent(event.agent_id)

            if agent is None:
                raise ValueError("Event agent does not exist.")

            alerts = []

            if event.severity >= cls.HIGH_SEVERITY_THRESHOLD:
                alert = cls._detect_high_severity_event(event)

                if alert is not None:
                    alerts.append(alert)

            if (
                event.category == "authentication"
                and event.event_type == "login.failed"
            ):
                alert = cls._detect_repeated_failed_logins(event)

                if alert is not None:
                    alerts.append(alert)

            session.flush()

            return alerts

        except Exception:
            session.rollback()
            raise

    @classmethod
    def _detect_high_severity_event(
        cls,
        event: SecurityEvent,
    ) -> Alert:
        rule_key = cls.HIGH_SEVERITY_RULE

        deduplication_key = cls._fingerprint(
            f"{event.agent_id}:{event.event_uid}"
        )

        existing = db.session.scalar(
            select(Alert)
            .where(
                Alert.rule_key == rule_key,
                Alert.deduplication_key == deduplication_key,
            )
            .with_for_update()
        )

        if existing is not None:
            return existing

        now = utcnow_naive()

        alert = Alert(
            rule_key=rule_key,
            title="High-severity security event",
            description=(
                f"An event with severity {event.severity} "
                f"was reported by the agent. "
                f"Event type: {event.event_type}."
            ),
            severity=event.severity,
            status="open",
            agent_id=event.agent_id,
            source_event_id=event.id,
            deduplication_key=deduplication_key,
            occurrence_count=1,
            first_seen_at=event.occurred_at,
            last_seen_at=event.occurred_at,
            created_at=now,
            updated_at=now,
        )

        db.session.add(alert)

        return alert

    @classmethod
    def _get_failed_login_window(
        cls,
        occurred_at: datetime,
    ) -> tuple[datetime, datetime]:
        if occurred_at.tzinfo is None:
            occurred_at = occurred_at.replace(
                tzinfo=timezone.utc
            )
        else:
            occurred_at = occurred_at.astimezone(timezone.utc)

        window_seconds = int(
            cls.FAILED_LOGIN_WINDOW.total_seconds()
        )

        timestamp = int(occurred_at.timestamp())
        bucket_timestamp = (
            timestamp // window_seconds
        ) * window_seconds

        window_start = datetime.fromtimestamp(
            bucket_timestamp,
            tz=timezone.utc,
        ).replace(tzinfo=None)

        window_end = window_start + cls.FAILED_LOGIN_WINDOW

        return window_start, window_end

    @classmethod
    def _detect_repeated_failed_logins(
        cls,
        event: SecurityEvent,
    ) -> Alert | None:
        event_data = event.event_data

        if not isinstance(event_data, dict):
            return None

        raw_username = event_data.get("username")

        if not isinstance(raw_username, str):
            return None

        username = raw_username.strip().lower()

        if not username or len(username) > 256:
            return None

        window_start, window_end = cls._get_failed_login_window(
            event.occurred_at
        )

        username_expression = func.lower(
            func.trim(
                SecurityEvent.event_data["username"].as_string()
            )
        )

        matching_events = db.session.scalars(
            select(SecurityEvent)
            .where(
                SecurityEvent.agent_id == event.agent_id,
                SecurityEvent.category == "authentication",
                SecurityEvent.event_type == "login.failed",
                SecurityEvent.occurred_at >= window_start,
                SecurityEvent.occurred_at < window_end,
                username_expression == username,
            )
            .order_by(
                SecurityEvent.occurred_at.asc(),
                SecurityEvent.id.asc(),
            )
        ).all()

        if len(matching_events) < cls.FAILED_LOGIN_THRESHOLD:
            return None

        rule_key = cls.REPEATED_FAILED_LOGINS_RULE

        # The username is included only in a one-way fingerprint.
        deduplication_key = cls._fingerprint(
            f"{event.agent_id}:{username}:{window_start.isoformat()}"
        )

        existing = db.session.scalar(
            select(Alert)
            .where(
                Alert.rule_key == rule_key,
                Alert.deduplication_key == deduplication_key,
            )
            .with_for_update()
        )

        first_seen = matching_events[0].occurred_at
        last_seen = matching_events[-1].occurred_at
        now = utcnow_naive()

        if existing is not None:
            existing.occurrence_count = len(matching_events)
            existing.last_seen_at = last_seen
            existing.updated_at = now

            # New evidence reopens an alert that was previously resolved
            # or acknowledged.
            if existing.status != "open":
                existing.status = "open"
                existing.acknowledged_by_user_id = None
                existing.acknowledged_at = None
                existing.resolved_at = None

            return existing

        alert = Alert(
            rule_key=rule_key,
            title="Repeated failed authentication attempts",
            description=(
                f"At least {cls.FAILED_LOGIN_THRESHOLD} failed "
                f"authentication events were recorded for the same "
                f"account within a five-minute UTC window."
            ),
            severity=8,
            status="open",
            agent_id=event.agent_id,
            source_event_id=event.id,
            deduplication_key=deduplication_key,
            occurrence_count=len(matching_events),
            first_seen_at=first_seen,
            last_seen_at=last_seen,
            created_at=now,
            updated_at=now,
        )

        db.session.add(alert)

        return alert
