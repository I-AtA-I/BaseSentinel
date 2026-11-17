import uuid

from sqlalchemy import Index, String, Uuid, UniqueConstraint

from basesentinel import db
from basesentinel.models.base import utcnow_naive


class AgentInvitation(db.Model):
    __tablename__ = "agent_invitations"

    id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        primary_key=True,
        default=uuid.uuid4,
    )
    token_hash = db.Column(String(64), nullable=False)
    created_by_user_id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        db.ForeignKey(
            "users.id",
            ondelete="RESTRICT",
            name="fk_agent_invitations_created_by_user_id_users",
        ),
        nullable=False,
    )
    created_at = db.Column(db.DateTime(), nullable=False, default=utcnow_naive)
    expires_at = db.Column(db.DateTime(), nullable=False)
    consumed_at = db.Column(db.DateTime(), nullable=True)
    revoked_at = db.Column(db.DateTime(), nullable=True)

    created_by = db.relationship("User")

    __table_args__ = (
        UniqueConstraint("token_hash", name="uq_agent_invitations_token_hash"),
        Index("ix_agent_invitations_expires_at", "expires_at"),
        Index("ix_agent_invitations_created_at", "created_at"),
    )
