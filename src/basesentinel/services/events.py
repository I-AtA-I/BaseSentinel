
import json
import re
import uuid

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from basesentinel import db
from basesentinel.models import Agent, SecurityEvent
from basesentinel.models.base import utcnow_naive


class InvalidEventPayloadError(ValueError):
    pass


class UnavailableAgentForIngestionError(Exception):
    pass


@dataclass(frozen=True)
class EventIngestionResult:
    event: SecurityEvent
    duplicate: bool


class EventIngestionService:
    SCHEMA_VERSION = 1
    MAX_EVENT_DATA_BYTES = 16 * 1024
    MAX_MESSAGE_LENGTH = 4096

    ALLOWED_CATEGORIES = {
        "authentication",
        "account",
        "process",
        "network",
        "file",
        "system",
        "service",
        "firewall",
        "application",
        "audit",
    }

    ALLOWED_FIELDS = {
        "event_uid",
        "schema_version",
        "category",
        "event_type",
        "severity",
        "source",
        "event_code",
        "message",
        "event_data",
        "occurred_at",
    }

    REQUIRED_FIELDS = {
        "event_uid",
        "schema_version",
        "category",
        "event_type",
        "severity",
        "source",
        "message",
        "occurred_at",
    }

    @staticmethod
    def _validate_text(
        value,
        field,
        max_length,
        allow_newlines=False,
    ):
        if not isinstance(value, str):
            raise InvalidEventPayloadError(
                f"Invalid {field}."
            )

        value = value.strip()

        if not value:
            raise InvalidEventPayloadError(
                f"{field} is required."
            )

        if len(value) > max_length:
            raise InvalidEventPayloadError(
                f"{field} is too long."
            )

        allowed_controls = {"\n", "\r", "\t"} if allow_newlines else set()

        if any(
            ord(character) < 32 and character not in allowed_controls
            for character in value
        ):
            raise InvalidEventPayloadError(
                f"Invalid characters in {field}."
            )

        return value

    @classmethod
    def _parse_event_uid(cls, value):
        if not isinstance(value, str):
            raise InvalidEventPayloadError("Invalid event UID.")

        try:
            return uuid.UUID(value)
        except (ValueError, AttributeError):
            raise InvalidEventPayloadError("Invalid event UID.") from None

    @classmethod
    def _parse_occurred_at(cls, value):
        if (
            not isinstance(value, str)
            or len(value) > 40
            or "T" not in value
        ):
            raise InvalidEventPayloadError(
                "Invalid event timestamp."
            )

        try:
            parsed = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
        except ValueError:
            raise InvalidEventPayloadError(
                "Invalid event timestamp."
            ) from None

        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise InvalidEventPayloadError(
                "Event timestamp must include a timezone."
            )

        return parsed.astimezone(timezone.utc).replace(tzinfo=None)

    @classmethod
    def _validate_event_data(cls, value):
        if value is None:
            return None

        if not isinstance(value, dict):
            raise InvalidEventPayloadError(
                "Event data must be a JSON object."
            )

        try:
            encoded = json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            )
            encoded_size = len(encoded.encode("utf-8"))
        except (TypeError, ValueError, UnicodeError, RecursionError):
            raise InvalidEventPayloadError(
                "Event data is not valid JSON."
            ) from None

        if encoded_size > cls.MAX_EVENT_DATA_BYTES:
            raise InvalidEventPayloadError(
                "Event data exceeds the maximum allowed size."
            )

        return value

    @classmethod
    def _normalize_payload(cls, payload):
        if not isinstance(payload, dict):
            raise InvalidEventPayloadError(
                "Event payload must be a JSON object."
            )

        unknown_fields = set(payload) - cls.ALLOWED_FIELDS

        if unknown_fields:
            raise InvalidEventPayloadError(
                "Event payload contains unsupported fields."
            )

        missing_fields = cls.REQUIRED_FIELDS - set(payload)

        if missing_fields:
            raise InvalidEventPayloadError(
                "Event payload is missing required fields."
            )

        schema_version = payload["schema_version"]

        if (
            type(schema_version) is not int
            or schema_version != cls.SCHEMA_VERSION
        ):
            raise InvalidEventPayloadError(
                "Unsupported event schema version."
            )

        severity = payload["severity"]

        if type(severity) is not int or not 0 <= severity <= 10:
            raise InvalidEventPayloadError(
                "Severity must be an integer between 0 and 10."
            )

        category = cls._validate_text(
            payload["category"],
            "category",
            32,
        ).lower()

        if category not in cls.ALLOWED_CATEGORIES:
            raise InvalidEventPayloadError(
                "Unsupported event category."
            )

        event_type = cls._validate_text(
            payload["event_type"],
            "event type",
            80,
        ).lower()

        if not re.fullmatch(r"[a-z][a-z0-9_.-]{0,79}", event_type):
            raise InvalidEventPayloadError(
                "Invalid event type."
            )

        source = cls._validate_text(
            payload["source"],
            "source",
            80,
        )

        message = cls._validate_text(
            payload["message"],
            "message",
            cls.MAX_MESSAGE_LENGTH,
            allow_newlines=True,
        )

        event_code = payload.get("event_code")

        if event_code is not None:
            if type(event_code) is int:
                event_code = str(event_code)
            elif isinstance(event_code, str):
                event_code = cls._validate_text(
                    event_code,
                    "event code",
                    64,
                )
            else:
                raise InvalidEventPayloadError(
                    "Invalid event code."
                )

        # Keep successful Windows logons informational even when they
        # were collected into a local queue by an older agent version.
        if (
            source == "Windows Security"
            and category == "authentication"
            and event_type == "login.success"
            and event_code == "4624"
        ):
            severity = 0

        return {
            "event_uid": cls._parse_event_uid(payload["event_uid"]),
            "schema_version": schema_version,
            "category": category,
            "event_type": event_type,
            "severity": severity,
            "source": source,
            "event_code": event_code,
            "message": message,
            "event_data": cls._validate_event_data(
                payload.get("event_data")
            ),
            "occurred_at": cls._parse_occurred_at(
                payload["occurred_at"]
            ),
        }

    @classmethod
    def ingest(cls, agent_id, payload):
        """Validate and store one event for an authenticated agent."""

        normalized = cls._normalize_payload(payload)
        session = db.session

        try:
            agent = session.scalar(
                select(Agent)
                .where(Agent.id == agent_id)
                .with_for_update()
            )
            if (
                agent is None
                or agent.status != "active"
                or agent.revoked_at is not None
                or agent.uninstalled_at is not None
            ):
                raise UnavailableAgentForIngestionError(
                    "Agent is unavailable."
                )

            event = SecurityEvent(
                agent_id=agent.id,
                event_uid=normalized["event_uid"],
                schema_version=normalized["schema_version"],
                category=normalized["category"],
                event_type=normalized["event_type"],
                severity=normalized["severity"],
                source=normalized["source"],
                event_code=normalized["event_code"],
                message=normalized["message"],
                event_data=normalized["event_data"],
                occurred_at=normalized["occurred_at"],
                received_at=utcnow_naive(),
            )

            session.add(event)

            # Persist the event inside the current transaction.
            # This also makes the generated event ID available.
            session.flush()

            # Evaluate detection rules before committing the event.
            # Detection and ingestion share the same database transaction.
            from basesentinel.services.detection import DetectionService

            DetectionService.process_event(event)

            session.commit()
            session.refresh(event)

            return EventIngestionResult(
                event=event,
                duplicate=False,
            )

        except IntegrityError:
            session.rollback()

            # The unique constraint handles concurrent duplicate requests.
            existing = session.scalar(
                select(SecurityEvent).where(
                    SecurityEvent.agent_id == agent_id,
                    SecurityEvent.event_uid == normalized["event_uid"],
                )
            )

            if existing is not None:
                return EventIngestionResult(
                    event=existing,
                    duplicate=True,
                )

            raise

        except Exception:
            session.rollback()
            raise
