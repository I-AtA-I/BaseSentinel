import uuid

from sqlalchemy import CheckConstraint, Index, String, Text, Uuid

from basesentinel import db
from basesentinel.models.base import utcnow_naive


class DetectionRule(db.Model):
    __tablename__ = "detection_rules"

    id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        primary_key=True,
        default=uuid.uuid4,
    )
    name = db.Column(String(120), nullable=False)
    description = db.Column(Text, nullable=False, default="")
    category = db.Column(String(32), nullable=True)
    event_type = db.Column(String(80), nullable=True)
    source = db.Column(String(80), nullable=True)
    event_code = db.Column(String(64), nullable=True)
    min_event_severity = db.Column(db.SmallInteger, nullable=True)
    conditions = db.Column(db.JSON, nullable=False, default=dict)
    threshold = db.Column(db.Integer, nullable=False, default=1)
    window_seconds = db.Column(db.Integer, nullable=False, default=300)
    severity = db.Column(db.SmallInteger, nullable=False, default=7)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    created_by_user_id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        db.ForeignKey(
            "users.id",
            ondelete="RESTRICT",
            name="fk_detection_rules_created_by_user_id_users",
        ),
        nullable=False,
    )
    created_at = db.Column(db.DateTime(), nullable=False, default=utcnow_naive)
    updated_at = db.Column(
        db.DateTime(),
        nullable=False,
        default=utcnow_naive,
        onupdate=utcnow_naive,
    )

    created_by = db.relationship("User")

    __table_args__ = (
        CheckConstraint("threshold BETWEEN 1 AND 100", name="ck_detection_rules_threshold"),
        CheckConstraint("window_seconds BETWEEN 1 AND 86400", name="ck_detection_rules_window"),
        CheckConstraint("severity BETWEEN 0 AND 10", name="ck_detection_rules_severity"),
        CheckConstraint(
            "min_event_severity IS NULL OR min_event_severity BETWEEN 0 AND 10",
            name="ck_detection_rules_min_event_severity",
        ),
        Index("ix_detection_rules_enabled", "enabled"),
    )
