"""Create persistent custom detection rules.

Revision ID: 7e3c9a1b5d42
Revises: c41d8a7f2e90
Create Date: 2026-11-22
"""

from alembic import op
import sqlalchemy as sa


revision = "7e3c9a1b5d42"
down_revision = "c41d8a7f2e90"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "detection_rules",
        sa.Column("id", sa.Uuid(as_uuid=True, native_uuid=False), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=True),
        sa.Column("event_type", sa.String(length=80), nullable=True),
        sa.Column("source", sa.String(length=80), nullable=True),
        sa.Column("event_code", sa.String(length=64), nullable=True),
        sa.Column("min_event_severity", sa.SmallInteger(), nullable=True),
        sa.Column("conditions", sa.JSON(), nullable=False),
        sa.Column("threshold", sa.Integer(), nullable=False),
        sa.Column("window_seconds", sa.Integer(), nullable=False),
        sa.Column("severity", sa.SmallInteger(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid(as_uuid=True, native_uuid=False), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint("threshold BETWEEN 1 AND 100", name="ck_detection_rules_threshold"),
        sa.CheckConstraint("window_seconds BETWEEN 1 AND 86400", name="ck_detection_rules_window"),
        sa.CheckConstraint("severity BETWEEN 0 AND 10", name="ck_detection_rules_severity"),
        sa.CheckConstraint(
            "min_event_severity IS NULL OR min_event_severity BETWEEN 0 AND 10",
            name="ck_detection_rules_min_event_severity",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            name="fk_detection_rules_created_by_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_detection_rules_enabled",
        "detection_rules",
        ["enabled"],
        unique=False,
    )


def downgrade():
    op.drop_index("ix_detection_rules_enabled", table_name="detection_rules")
    op.drop_table("detection_rules")
