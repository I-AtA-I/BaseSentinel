
import hashlib

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from basesentinel import db
from basesentinel.models import Agent, Alert, DetectionRule, SecurityEvent
from basesentinel.models.base import utcnow_naive


class DetectionService:
    HIGH_SEVERITY_RULE = "high_severity_event"
    REPEATED_FAILED_LOGINS_RULE = "repeated_failed_logins"

    HIGH_SEVERITY_THRESHOLD = 8
    IMPORTANT_EVENT_RULE = "important_security_event"
    IMPORTANT_EVENT_RULES = {
        "device.usb_storage_recognized": (
            "USB storage device recognized",
            "Windows recognized a USB mass-storage device. Multiple Security event 6416 records for the same device are correlated into this alert.",
            8,
        ),
        "service.installed": (
            "Windows service installed",
            "A new Windows service was installed. Review its publisher and executable path.",
            8,
        ),
        "audit.policy_changed": (
            "Windows audit policy changed",
            "The Windows audit policy was modified.",
            8,
        ),
        "security_log.cleared": (
            "Windows Security log cleared",
            "The Windows Security event log was cleared.",
            10,
        ),
        "account.deleted": (
            "Windows account deleted",
            "A Windows user account was deleted.",
            8,
        ),
        "group.member_added": (
            "Account added to a security group",
            "A Windows account was added to a security group. Verify the target group and account.",
            8,
        ),
        "account.created": (
            "Windows account created",
            "A new Windows account was created. Verify the requester and intended owner.",
            8,
        ),
        "account.enabled": (
            "Windows account enabled",
            "A Windows account was enabled. Verify that the change was authorized.",
            8,
        ),
        "password.reset": (
            "Windows account password reset",
            "A Windows account password reset was attempted. Verify the requester and target account.",
            8,
        ),
        "group.member_removed": (
            "Account removed from a security group",
            "A Windows account was removed from a security group. Verify the change.",
            8,
        ),
        "malware.detected": (
            "Malware detected by Microsoft Defender",
            "Microsoft Defender reported a malware detection. Review the threat name, affected path, and remediation status.",
            10,
        ),
        "malware.remediation_failed": (
            "Malware remediation failed",
            "Microsoft Defender could not complete a remediation action. Investigate the affected endpoint.",
            10,
        ),
        "attack_surface_reduction.blocked": (
            "Attack surface reduction rule blocked activity",
            "Microsoft Defender Attack Surface Reduction blocked an action. Review the process and rule details.",
            8,
        ),
    }
    FAILED_LOGIN_THRESHOLD = 5
    FAILED_LOGIN_WINDOW = timedelta(minutes=5)

    @staticmethod
    def _fingerprint(value: str) -> str:
        return hashlib.sha256(
            value.encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _usb_storage_device_id(event: SecurityEvent) -> str | None:
        event_data = event.event_data
        if not isinstance(event_data, dict):
            return None

        raw_device_id = event_data.get("DeviceId")
        if not isinstance(raw_device_id, str):
            return None

        device_id = raw_device_id.strip().casefold()
        return device_id or None

    @classmethod
    def _important_event_deduplication_key(cls, event: SecurityEvent) -> str:
        if event.event_type == "device.usb_storage_recognized":
            device_id = cls._usb_storage_device_id(event)
            if device_id is not None:
                return cls._fingerprint(
                    f"{event.agent_id}:usb-storage:{device_id}"
                )

        return cls._fingerprint(f"{event.agent_id}:{event.event_uid}")

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

            important_rule = cls.IMPORTANT_EVENT_RULES.get(event.event_type)
            if important_rule is not None:
                alert = cls._detect_important_event(event, important_rule)
                if alert is not None:
                    alerts.append(alert)
            elif event.severity >= cls.HIGH_SEVERITY_THRESHOLD:
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

            alerts.extend(cls._detect_custom_rules(event))

            session.flush()

            return alerts

        except Exception:
            session.rollback()
            raise

    @classmethod
    def _detect_important_event(
        cls,
        event: SecurityEvent,
        rule: tuple[str, str, int],
    ) -> Alert:
        title, description, severity = rule
        deduplication_key = cls._important_event_deduplication_key(event)
        existing = db.session.scalar(
            select(Alert)
            .where(
                Alert.rule_key == cls.IMPORTANT_EVENT_RULE,
                Alert.deduplication_key == deduplication_key,
            )
            .with_for_update()
        )
        if existing is not None:
            if event.event_type == "device.usb_storage_recognized":
                device_id = cls._usb_storage_device_id(event)
                if device_id is not None:
                    device_id_expression = func.lower(
                        func.trim(SecurityEvent.event_data["DeviceId"].as_string())
                    )
                    matching_events = db.session.scalars(
                        select(SecurityEvent)
                        .where(
                            SecurityEvent.agent_id == event.agent_id,
                            SecurityEvent.event_type == "device.usb_storage_recognized",
                            device_id_expression == device_id,
                        )
                        .order_by(SecurityEvent.occurred_at.asc(), SecurityEvent.id.asc())
                    ).all()
                    if matching_events:
                        existing.occurrence_count = len(matching_events)
                        existing.first_seen_at = matching_events[0].occurred_at
                        existing.last_seen_at = matching_events[-1].occurred_at
                        existing.updated_at = utcnow_naive()
            return existing

        now = utcnow_naive()
        alert = Alert(
            rule_key=cls.IMPORTANT_EVENT_RULE,
            title=title,
            description=(
                f"{description} Source: {event.source}. "
                f"Event: {event.event_type}. "
                f"Details: {event.message[:1000]}"
            ),
            severity=severity,
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


    @classmethod
    def _detect_custom_rules(cls, event: SecurityEvent) -> list[Alert]:
        """Evaluate enabled administrator-defined rules for one event."""
        rules = db.session.scalars(
            select(DetectionRule).where(DetectionRule.enabled.is_(True))
        ).all()
        created_or_updated = []

        for rule in rules:
            if rule.category is not None and event.category != rule.category:
                continue
            if rule.event_type is not None and event.event_type != rule.event_type:
                continue
            if rule.source is not None and event.source.casefold() != rule.source.casefold():
                continue
            if rule.event_code is not None and event.event_code != rule.event_code:
                continue
            if (
                rule.min_event_severity is not None
                and event.severity < rule.min_event_severity
            ):
                continue
            if not cls._matches_custom_conditions(event, rule.conditions):
                continue

            event_time = event.occurred_at.replace(tzinfo=timezone.utc)
            timestamp = int(event_time.timestamp())
            bucket_start = (
                timestamp // rule.window_seconds
            ) * rule.window_seconds
            window_start = datetime.fromtimestamp(
                bucket_start, tz=timezone.utc
            ).replace(tzinfo=None)
            window_end = window_start + timedelta(seconds=rule.window_seconds)

            query = select(SecurityEvent).where(
                SecurityEvent.agent_id == event.agent_id,
                SecurityEvent.occurred_at >= window_start,
                SecurityEvent.occurred_at < window_end,
            )
            if rule.category is not None:
                query = query.where(SecurityEvent.category == rule.category)
            if rule.event_type is not None:
                query = query.where(SecurityEvent.event_type == rule.event_type)
            if rule.source is not None:
                query = query.where(func.lower(SecurityEvent.source) == rule.source.casefold())
            if rule.event_code is not None:
                query = query.where(SecurityEvent.event_code == rule.event_code)
            if rule.min_event_severity is not None:
                query = query.where(SecurityEvent.severity >= rule.min_event_severity)

            candidates = db.session.scalars(
                query.order_by(SecurityEvent.occurred_at.asc(), SecurityEvent.id.asc())
                .limit(1001)
            ).all()
            matches = [
                candidate for candidate in candidates
                if cls._matches_custom_conditions(candidate, rule.conditions)
            ]
            if len(matches) < rule.threshold:
                continue

            rule_key = f"custom_{rule.id.hex}"
            deduplication_key = cls._fingerprint(
                f"{rule.id}:{event.agent_id}:{bucket_start}"
            )
            existing = db.session.scalar(
                select(Alert)
                .where(
                    Alert.rule_key == rule_key,
                    Alert.deduplication_key == deduplication_key,
                )
                .with_for_update()
            )
            first_seen = matches[0].occurred_at
            last_seen = matches[-1].occurred_at
            now = utcnow_naive()

            if existing is not None:
                existing.occurrence_count = len(matches)
                existing.last_seen_at = last_seen
                existing.source_event_id = event.id
                existing.updated_at = now
                if existing.status != "open":
                    existing.status = "open"
                    existing.acknowledged_by_user_id = None
                    existing.acknowledged_at = None
                    existing.resolved_at = None
                created_or_updated.append(existing)
                continue

            criteria = []
            for field in ("category", "event_type", "source", "event_code"):
                value = getattr(rule, field)
                if value is not None:
                    criteria.append(f"{field}={value}")
            if rule.min_event_severity is not None:
                criteria.append(f"severity>={rule.min_event_severity}")
            if rule.conditions:
                criteria.append(f"event_data matches {len(rule.conditions)} condition(s)")
            criteria_text = ", ".join(criteria) if criteria else "all events"
            description = rule.description.strip()
            explanation = (
                f"Custom rule matched {len(matches)} event(s) within "
                f"{rule.window_seconds} seconds on this agent. "
                f"Criteria: {criteria_text}."
            )
            if description:
                explanation = f"{description} {explanation}"

            alert = Alert(
                rule_key=rule_key,
                title=rule.name,
                description=explanation[:4000],
                severity=rule.severity,
                status="open",
                agent_id=event.agent_id,
                source_event_id=event.id,
                deduplication_key=deduplication_key,
                occurrence_count=len(matches),
                first_seen_at=first_seen,
                last_seen_at=last_seen,
                created_at=now,
                updated_at=now,
            )
            db.session.add(alert)
            created_or_updated.append(alert)

        return created_or_updated

    @staticmethod
    def _matches_custom_conditions(
        event: SecurityEvent,
        conditions: dict,
    ) -> bool:
        if not conditions:
            return True
        event_data = event.event_data
        if not isinstance(event_data, dict):
            return False
        return all(
            key in event_data and event_data[key] == expected
            for key, expected in conditions.items()
        )
