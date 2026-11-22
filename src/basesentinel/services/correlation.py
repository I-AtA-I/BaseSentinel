import hashlib
import json
from datetime import timedelta

from sqlalchemy import select

from basesentinel import db
from basesentinel.models import CorrelatedActivity, CorrelatedActivityEvent
from basesentinel.models.base import utcnow_naive


class CorrelationService:
    """Build durable, explainable activities from immutable source events."""

    PRIVILEGE_ASSIGNMENT_TYPE = "windows.privilege_assignment"
    PRIVILEGE_ASSIGNMENT_WINDOW = timedelta(minutes=5)

    @staticmethod
    def _clean(value):
        if value is None:
            return ""
        return " ".join(str(value).strip().split())

    @classmethod
    def _privilege_identity(cls, event):
        data = event.event_data if isinstance(event.event_data, dict) else {}
        account = cls._clean(
            data.get("SubjectUserSid") or data.get("SubjectUserName")
        ).casefold()
        domain = cls._clean(data.get("SubjectDomainName")).casefold()
        logon_id = cls._clean(data.get("SubjectLogonId")).casefold()
        raw_privileges = cls._clean(data.get("PrivilegeList"))
        privileges = sorted(
            item.casefold() for item in raw_privileges.split() if item
        )
        if not account or not logon_id or not privileges:
            return None
        identity = {
            "agent_id": str(event.agent_id),
            "account": account,
            "domain": domain,
            "logon_id": logon_id,
            "privileges": privileges,
        }
        canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest(), identity

    @classmethod
    def process_event(cls, event):
        if event.id is None:
            raise ValueError("Event must be persisted before correlation.")
        if event.event_code != "4672" or event.event_type != "privilege.special_assignment":
            return None

        resolved = cls._privilege_identity(event)
        if resolved is None:
            # Missing identity fields: retain visibility, but never merge on weak evidence.
            key_material = f"{event.agent_id}:4672:incomplete:{event.event_uid}"
            context = {"correlation_quality": "incomplete"}
        else:
            identity_key, identity = resolved
            key_material = f"{event.agent_id}:4672:{identity_key}"
            context = {
                "correlation_quality": "structured",
                "account": identity["account"],
                "domain": identity["domain"],
                "logon_id": identity["logon_id"],
                "privileges": identity["privileges"],
            }

        correlation_key = hashlib.sha256(key_material.encode("utf-8")).hexdigest()
        start = event.occurred_at - cls.PRIVILEGE_ASSIGNMENT_WINDOW
        end = event.occurred_at + cls.PRIVILEGE_ASSIGNMENT_WINDOW
        activity = db.session.scalar(
            select(CorrelatedActivity)
            .where(
                CorrelatedActivity.activity_type == cls.PRIVILEGE_ASSIGNMENT_TYPE,
                CorrelatedActivity.correlation_key == correlation_key,
                CorrelatedActivity.last_seen_at >= start,
                CorrelatedActivity.last_seen_at <= end,
            )
            .with_for_update()
        )

        now = utcnow_naive()
        if activity is None:
            activity = CorrelatedActivity(
                agent_id=event.agent_id,
                activity_type=cls.PRIVILEGE_ASSIGNMENT_TYPE,
                correlation_key=correlation_key,
                title="Special privileges assigned",
                summary="Windows assigned special privileges to a logon session.",
                context=context,
                occurrence_count=0,
                first_seen_at=event.occurred_at,
                last_seen_at=event.occurred_at,
                created_at=now,
                updated_at=now,
            )
            db.session.add(activity)
            db.session.flush()

        linked = db.session.scalar(
            select(CorrelatedActivityEvent.id).where(
                CorrelatedActivityEvent.activity_id == activity.id,
                CorrelatedActivityEvent.event_id == event.id,
            )
        )
        if linked is None:
            db.session.add(CorrelatedActivityEvent(
                activity_id=activity.id,
                event_id=event.id,
            ))
            activity.occurrence_count += 1
            activity.first_seen_at = min(activity.first_seen_at, event.occurred_at)
            activity.last_seen_at = max(activity.last_seen_at, event.occurred_at)
            activity.updated_at = now

        return activity
