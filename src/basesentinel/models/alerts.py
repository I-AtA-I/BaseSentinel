
import uuid

from sqlalchemy import (
    CheckConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)

from basesentinel import db
from basesentinel.models.base import utcnow_naive


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        primary_key=True,
        default=uuid.uuid4,
    )

    rule_key = db.Column(
        String(64),
        nullable=False,
    )

    title = db.Column(
        String(160),
        nullable=False,
    )

    description = db.Column(
        Text,
        nullable=False,
    )

    severity = db.Column(
        db.SmallInteger,
        nullable=False,
    )

    status = db.Column(
        String(24),
        nullable=False,
        default="open",
    )

    agent_id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        db.ForeignKey(
            "agents.id",
            ondelete="RESTRICT",
            name="fk_alerts_agent_id_agents",
        ),
        nullable=False,
    )

    source_event_id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        db.ForeignKey(
            "security_events.id",
            ondelete="RESTRICT",
            name="fk_alerts_source_event_id_security_events",
        ),
        nullable=False,
    )

    # SHA-256 fingerprint used for alert deduplication.
    deduplication_key = db.Column(
        String(64),
        nullable=False,
    )

    occurrence_count = db.Column(
        Integer,
        nullable=False,
        default=1,
    )

    first_seen_at = db.Column(
        db.DateTime(),
        nullable=False,
        default=utcnow_naive,
    )

    last_seen_at = db.Column(
        db.DateTime(),
        nullable=False,
        default=utcnow_naive,
    )

    acknowledged_by_user_id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        db.ForeignKey(
            "users.id",
            ondelete="RESTRICT",
            name="fk_alerts_acknowledged_by_user_id_users",
        ),
        nullable=True,
    )

    acknowledged_at = db.Column(
        db.DateTime(),
        nullable=True,
    )

    resolved_at = db.Column(
        db.DateTime(),
        nullable=True,
    )

    created_at = db.Column(
        db.DateTime(),
        nullable=False,
        default=utcnow_naive,
    )

    updated_at = db.Column(
        db.DateTime(),
        nullable=False,
        default=utcnow_naive,
        onupdate=utcnow_naive,
    )

    agent = db.relationship("Agent")

    source_event = db.relationship("SecurityEvent")

    acknowledged_by = db.relationship("User")

    __table_args__ = (
        UniqueConstraint(
            "rule_key",
            "deduplication_key",
            name="uq_alerts_rule_deduplication",
        ),
        CheckConstraint(
            "severity BETWEEN 0 AND 10",
            name="ck_alerts_severity_range",
        ),
        CheckConstraint(
            "status IN ('open', 'acknowledged', 'resolved')",
            name="ck_alerts_status",
        ),
        CheckConstraint(
            "occurrence_count >= 1",
            name="ck_alerts_occurrence_count",
        ),
        Index(
            "ix_alerts_status_last_seen",
            "status",
            "last_seen_at",
        ),
        Index(
            "ix_alerts_agent_last_seen",
            "agent_id",
            "last_seen_at",
        ),
        Index(
            "ix_alerts_severity_last_seen",
            "severity",
            "last_seen_at",
        ),
    )
