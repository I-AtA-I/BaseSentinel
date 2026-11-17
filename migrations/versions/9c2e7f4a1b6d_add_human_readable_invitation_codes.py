"""add human-readable invitation codes

Revision ID: 9c2e7f4a1b6d
Revises: 7a91c3e5d2f0
Create Date: 2026-11-17
"""
from alembic import op
import sqlalchemy as sa

revision = "9c2e7f4a1b6d"
down_revision = "7a91c3e5d2f0"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "agent_invitations",
        sa.Column("code_hash", sa.String(length=64), nullable=True),
    )
    op.create_unique_constraint(
        op.f("uq_agent_invitations_code_hash"),
        "agent_invitations",
        ["code_hash"],
    )


def downgrade():
    op.drop_constraint(
        op.f("uq_agent_invitations_code_hash"),
        "agent_invitations",
        type_="unique",
    )
    op.drop_column("agent_invitations", "code_hash")
