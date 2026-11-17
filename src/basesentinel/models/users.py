import uuid

from sqlalchemy import Boolean, Index, String, UniqueConstraint, Uuid

from basesentinel import db
from basesentinel.models.base import utcnow_naive


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        primary_key=True,
        default=uuid.uuid4,
    )

    username = db.Column(String(64), nullable=False)
    password_hash = db.Column(String(255), nullable=False)

    role = db.Column(
        String(24),
        nullable=False,
        default="viewer",
    )

    is_active = db.Column(
        Boolean,
        nullable=False,
        default=True,
    )

    last_login_at = db.Column(db.DateTime(), nullable=True)

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

    created_pairing_codes = db.relationship(
        "PairingCode",
        back_populates="created_by",
        passive_deletes="all",
    )

    __table_args__ = (
        UniqueConstraint(
            "username",
            name="uq_users_username",
        ),
        Index("ix_users_is_active", "is_active"),
    )