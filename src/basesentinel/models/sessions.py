
import uuid

from sqlalchemy import Index, String, Uuid

from basesentinel import db
from basesentinel.models.base import utcnow_naive


class UserSession(db.Model):
    __tablename__ = "user_sessions"

    id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        primary_key=True,
        default=uuid.uuid4,
    )

    user_id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        db.ForeignKey(
            "users.id",
            name="fk_user_sessions_user_id_users",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )

    token_hash = db.Column(
        String(64),
        nullable=False,
        unique=True,
    )

    created_at = db.Column(
        db.DateTime(),
        nullable=False,
        default=utcnow_naive,
    )

    expires_at = db.Column(
        db.DateTime(),
        nullable=False,
    )

    revoked_at = db.Column(
        db.DateTime(),
        nullable=True,
    )

    last_used_at = db.Column(
        db.DateTime(),
        nullable=True,
    )

    __table_args__ = (
        Index("ix_user_sessions_user_id", "user_id"),
        Index("ix_user_sessions_expires_at", "expires_at"),
    )
