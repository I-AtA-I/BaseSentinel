import uuid

from sqlalchemy import (
    Index,
    SmallInteger,
    String,
    UniqueConstraint,
    Uuid,
)

from basesentinel import db
from basesentinel.models.base import utcnow_naive


class Agent(db.Model):
    __tablename__ = "agents"

    id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        primary_key=True,
        default=uuid.uuid4,
    )

    asset_id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        db.ForeignKey(
            "assets.id",
            ondelete="RESTRICT",
            name="fk_agents_asset_id_assets",
        ),
        nullable=False,
    )

    platform = db.Column(String(24), nullable=False)
    platform_version = db.Column(String(80), nullable=True)
    architecture = db.Column(String(32), nullable=True)
    agent_version = db.Column(String(40), nullable=False)

    status = db.Column(
        String(24),
        nullable=False,
        default="active",
    )

    enrolled_at = db.Column(
        db.DateTime(),
        nullable=False,
        default=utcnow_naive,
    )

    last_checkin_at = db.Column(
        db.DateTime(),
        nullable=False,
        default=utcnow_naive,
    )

    revoked_at = db.Column(db.DateTime(), nullable=True)
    uninstalled_at = db.Column(db.DateTime(), nullable=True)

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

    asset = db.relationship(
        "Asset",
        back_populates="agents",
    )

    credentials = db.relationship(
        "AgentCredential",
        back_populates="agent",
        passive_deletes="all",
    )

    consumed_pairing_codes = db.relationship(
        "PairingCode",
        back_populates="consumed_by_agent",
        foreign_keys="PairingCode.consumed_by_agent_id",
        passive_deletes="all",
    )

    __table_args__ = (
        Index(
            "ix_agents_asset_status",
            "asset_id",
            "status",
        ),
        Index(
            "ix_agents_last_checkin",
            "last_checkin_at",
        ),
    )


class AgentCredential(db.Model):
    __tablename__ = "agent_credentials"

    id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        primary_key=True,
        default=uuid.uuid4,
    )

    agent_id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        db.ForeignKey(
            "agents.id",
            ondelete="RESTRICT",
            name="fk_agent_credentials_agent_id_agents",
        ),
        nullable=False,
    )

    secret_hash = db.Column(String(64), nullable=False)

    created_at = db.Column(
        db.DateTime(),
        nullable=False,
        default=utcnow_naive,
    )

    expires_at = db.Column(
        db.DateTime(),
        nullable=False,
    )

    revoked_at = db.Column(db.DateTime(), nullable=True)
    last_used_at = db.Column(db.DateTime(), nullable=True)

    agent = db.relationship(
        "Agent",
        back_populates="credentials",
    )

    __table_args__ = (
        UniqueConstraint(
            "secret_hash",
            name="uq_agent_credentials_secret_hash",
        ),
        Index(
            "ix_agent_credentials_agent_revoked",
            "agent_id",
            "revoked_at",
        ),
    )


class PairingCode(db.Model):
    __tablename__ = "pairing_codes"

    id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        primary_key=True,
        default=uuid.uuid4,
    )

    code_hash = db.Column(String(64), nullable=False)

    created_by_user_id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        db.ForeignKey(
            "users.id",
            ondelete="RESTRICT",
            name="fk_pairing_codes_created_by_user_id_users",
        ),
        nullable=False,
    )

    target_asset_id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        db.ForeignKey(
            "assets.id",
            ondelete="RESTRICT",
            name="fk_pairing_codes_target_asset_id_assets",
        ),
        nullable=True,
    )

    consumed_by_agent_id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        db.ForeignKey(
            "agents.id",
            ondelete="RESTRICT",
            name="fk_pairing_codes_consumed_by_agent_id_agents",
        ),
        nullable=True,
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

    consumed_at = db.Column(db.DateTime(), nullable=True)
    revoked_at = db.Column(db.DateTime(), nullable=True)

    attempt_count = db.Column(
        SmallInteger,
        nullable=False,
        default=0,
    )

    created_by = db.relationship(
        "User",
        back_populates="created_pairing_codes",
    )

    target_asset = db.relationship(
        "Asset",
        foreign_keys=[target_asset_id],
    )

    consumed_by_agent = db.relationship(
        "Agent",
        back_populates="consumed_pairing_codes",
        foreign_keys=[consumed_by_agent_id],
    )

    __table_args__ = (
        UniqueConstraint(
            "code_hash",
            name="uq_pairing_codes_code_hash",
        ),
        Index(
            "ix_pairing_codes_expires_at",
            "expires_at",
        ),
        Index(
            "ix_pairing_codes_creator_created",
            "created_by_user_id",
            "created_at",
        ),
        Index(
            "ix_pairing_codes_consumed_at",
            "consumed_at",
        ),
    )