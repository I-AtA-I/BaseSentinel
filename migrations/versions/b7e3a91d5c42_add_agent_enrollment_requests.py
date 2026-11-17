"""add agent enrollment approval requests

Revision ID: b7e3a91d5c42
Revises: 9c2e7f4a1b6d
Create Date: 2026-11-17
"""
from alembic import op
import sqlalchemy as sa

revision = "b7e3a91d5c42"
down_revision = "9c2e7f4a1b6d"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "agent_enrollment_requests",
        sa.Column("id", sa.Uuid(native_uuid=False), nullable=False),
        sa.Column("invitation_id", sa.Uuid(native_uuid=False), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("platform", sa.String(length=24), nullable=False),
        sa.Column("platform_version", sa.String(length=80), nullable=True),
        sa.Column("architecture", sa.String(length=32), nullable=True),
        sa.Column("agent_version", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("requested_at", sa.DateTime(), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(), nullable=True),
        sa.Column("reviewed_by_user_id", sa.Uuid(native_uuid=False), nullable=True),
        sa.ForeignKeyConstraint(
            ["invitation_id"],
            ["agent_invitations.id"],
            name=op.f("fk_agent_enrollment_requests_invitation_id_agent_invitations"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["reviewed_by_user_id"],
            ["users.id"],
            name=op.f("fk_agent_enrollment_requests_reviewed_by_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_enrollment_requests")),
        sa.UniqueConstraint("invitation_id", name=op.f("uq_agent_enrollment_requests_invitation_id")),
    )
    op.create_index(
        "ix_agent_enrollment_requests_status_requested",
        "agent_enrollment_requests",
        ["status", "requested_at"],
    )


def downgrade():
    op.drop_index("ix_agent_enrollment_requests_status_requested", table_name="agent_enrollment_requests")
    op.drop_table("agent_enrollment_requests")
