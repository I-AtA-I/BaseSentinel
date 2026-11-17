import uuid

from sqlalchemy import Index, String, Uuid

from basesentinel import db
from basesentinel.models.base import utcnow_naive


class AgentEnrollmentRequest(db.Model):
    __tablename__ = "agent_enrollment_requests"

    id = db.Column(Uuid(as_uuid=True, native_uuid=False), primary_key=True, default=uuid.uuid4)
    invitation_id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        db.ForeignKey(
            "agent_invitations.id",
            ondelete="RESTRICT",
            name="fk_agent_enrollment_requests_invitation_id_agent_invitations",
        ),
        nullable=False,
        unique=True,
    )
    hostname = db.Column(String(255), nullable=False)
    platform = db.Column(String(24), nullable=False)
    platform_version = db.Column(String(80), nullable=True)
    architecture = db.Column(String(32), nullable=True)
    agent_version = db.Column(String(40), nullable=False)
    status = db.Column(String(24), nullable=False, default="pending")
    requested_at = db.Column(db.DateTime(), nullable=False, default=utcnow_naive)
    reviewed_at = db.Column(db.DateTime(), nullable=True)
    reviewed_by_user_id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        db.ForeignKey(
            "users.id",
            ondelete="RESTRICT",
            name="fk_agent_enrollment_requests_reviewed_by_user_id_users",
        ),
        nullable=True,
    )

    invitation = db.relationship("AgentInvitation")
    reviewed_by = db.relationship("User")

    __table_args__ = (
        Index("ix_agent_enrollment_requests_status_requested", "status", "requested_at"),
    )
