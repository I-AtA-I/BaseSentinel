
import uuid

from sqlalchemy import ForeignKey, Index, SmallInteger, String, Uuid
from basesentinel import db
from basesentinel.models.base import utcnow_naive


class Asset(db.Model):
    __tablename__ = "assets"

    agents = db.relationship(
        "Agent",
        back_populates="asset",
        passive_deletes="all",
    )

    id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        primary_key=True,
        default=uuid.uuid4,
    )

    display_name = db.Column(String(120), nullable=False)
    hostname = db.Column(String(255), nullable=True)
    fqdn = db.Column(String(253), nullable=True)

    asset_type = db.Column(
        String(32),
        nullable=False,
        default="unknown",
    )

    vendor = db.Column(String(120), nullable=True)
    model = db.Column(String(120), nullable=True)
    os_name = db.Column(String(80), nullable=True)
    os_version = db.Column(String(80), nullable=True)

    lifecycle_state = db.Column(
        String(24),
        nullable=False,
        default="active",
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

    interfaces = db.relationship(
        "AssetInterface",
        back_populates="asset",
        passive_deletes="all",
    )

    __table_args__ = (
        Index("ix_assets_hostname", "hostname"),
        Index(
            "ix_assets_state_last_seen",
            "lifecycle_state",
            "last_seen_at",
        ),
    )


class AssetInterface(db.Model):
    __tablename__ = "asset_interfaces"

    id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        primary_key=True,
        default=uuid.uuid4,
    )

    asset_id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        ForeignKey("assets.id", ondelete="RESTRICT"),
        nullable=False,
    )

    interface_key = db.Column(String(128), nullable=True)
    interface_name = db.Column(String(128), nullable=True)
    interface_type = db.Column(String(32), nullable=True)
    mac_address = db.Column(String(17), nullable=True)

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

    asset = db.relationship(
        "Asset",
        back_populates="interfaces",
    )

    addresses = db.relationship(
        "AssetAddress",
        back_populates="interface",
        passive_deletes="all",
    )

    __table_args__ = (
        db.UniqueConstraint(
            "asset_id",
            "interface_key",
            name="uq_asset_interfaces_asset_key",
        ),
        Index("ix_asset_interfaces_mac", "mac_address"),
    )


class AssetAddress(db.Model):
    __tablename__ = "asset_addresses"

    id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        primary_key=True,
        default=uuid.uuid4,
    )

    interface_id = db.Column(
        Uuid(as_uuid=True, native_uuid=False),
        ForeignKey("asset_interfaces.id", ondelete="RESTRICT"),
        nullable=False,
    )

    ip_address = db.Column(String(45), nullable=False)
    prefix_length = db.Column(SmallInteger, nullable=True)
    network_scope = db.Column(String(128), nullable=True)

    valid_from = db.Column(
        db.DateTime(),
        nullable=False,
        default=utcnow_naive,
    )

    last_seen_at = db.Column(
        db.DateTime(),
        nullable=False,
        default=utcnow_naive,
    )

    valid_until = db.Column(db.DateTime(), nullable=True)

    interface = db.relationship(
        "AssetInterface",
        back_populates="addresses",
    )

    __table_args__ = (
        Index(
            "ix_asset_addresses_ip_last_seen",
            "ip_address",
            "last_seen_at",
        ),
        Index(
            "ix_asset_addresses_interface_valid_from",
            "interface_id",
            "valid_from",
        ),
        Index(
            "ix_asset_addresses_network_scope",
            "network_scope",
        ),
    )
