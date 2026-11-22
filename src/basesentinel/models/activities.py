import uuid

from sqlalchemy import Index, Integer, JSON, String, Text, UniqueConstraint, Uuid

from basesentinel import db
from basesentinel.models.base import utcnow_naive


class CorrelatedActivity(db.Model):
    __tablename__ = "correlated_activities"

    id = db.Column(Uuid(as_uuid=True, native_uuid=False), primary_key=True, default=uuid.uuid4)
    agent_id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        db.ForeignKey("agents.id", ondelete="RESTRICT", name="fk_correlated_activities_agent_id_agents"),
        nullable=False,
    )
    activity_type = db.Column(String(80), nullable=False)
    correlation_key = db.Column(String(64), nullable=False)
    title = db.Column(String(160), nullable=False)
    summary = db.Column(Text, nullable=False)
    context = db.Column(JSON, nullable=False, default=dict)
    occurrence_count = db.Column(Integer, nullable=False, default=1)
    first_seen_at = db.Column(db.DateTime(), nullable=False)
    last_seen_at = db.Column(db.DateTime(), nullable=False)
    created_at = db.Column(db.DateTime(), nullable=False, default=utcnow_naive)
    updated_at = db.Column(db.DateTime(), nullable=False, default=utcnow_naive, onupdate=utcnow_naive)

    agent = db.relationship("Agent")
    source_events = db.relationship(
        "SecurityEvent",
        secondary="correlated_activity_events",
        lazy="selectin",
        order_by="SecurityEvent.occurred_at",
    )

    __table_args__ = (
        UniqueConstraint("activity_type", "correlation_key", name="uq_correlated_activities_type_key"),
        Index("ix_correlated_activities_agent_last_seen", "agent_id", "last_seen_at"),
        Index("ix_correlated_activities_last_seen", "last_seen_at"),
    )


class CorrelatedActivityEvent(db.Model):
    __tablename__ = "correlated_activity_events"

    id = db.Column(Uuid(as_uuid=True, native_uuid=False), primary_key=True, default=uuid.uuid4)
    activity_id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        db.ForeignKey("correlated_activities.id", ondelete="CASCADE", name="fk_correlated_activity_events_activity_id"),
        nullable=False,
    )
    event_id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        db.ForeignKey("security_events.id", ondelete="RESTRICT", name="fk_correlated_activity_events_event_id"),
        nullable=False,
    )
    created_at = db.Column(db.DateTime(), nullable=False, default=utcnow_naive)

    __table_args__ = (
        UniqueConstraint("activity_id", "event_id", name="uq_correlated_activity_events_pair"),
        Index("ix_correlated_activity_events_event", "event_id"),
    )
