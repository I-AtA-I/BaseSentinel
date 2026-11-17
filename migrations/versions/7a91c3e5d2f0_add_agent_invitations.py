"""add one-time agent invitations

Revision ID: 7a91c3e5d2f0
Revises: 4d8b9c2a1f70
Create Date: 2026-11-17
"""
from alembic import op
import sqlalchemy as sa

revision = "7a91c3e5d2f0"
down_revision = "4d8b9c2a1f70"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "agent_invitations",
        sa.Column("id", sa.Uuid(native_uuid=False), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("created_by_user_id", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("consumed_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            name=op.f("fk_agent_invitations_created_by_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_invitations")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_agent_invitations_token_hash")),
        sa.UniqueConstraint("code_hash", name=op.f("uq_agent_invitations_code_hash")),
    )
    op.create_index(
        "ix_agent_invitations_expires_at",
        "agent_invitations",
        ["expires_at"],
    )
    op.create_index(
        "ix_agent_invitations_created_at",
        "agent_invitations",
        ["created_at"],
    )


def downgrade():
    op.drop_index("ix_agent_invitations_created_at", table_name="agent_invitations")
    op.drop_index("ix_agent_invitations_expires_at", table_name="agent_invitations")
    op.drop_table("agent_invitations")
