"""add server enrollment settings

Revision ID: 4d8b9c2a1f70
Revises: 3b2afb33c2c5
Create Date: 2026-11-17
"""
from alembic import op
import sqlalchemy as sa

revision = "4d8b9c2a1f70"
down_revision = "3b2afb33c2c5"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "server_settings",
        sa.Column("id", sa.SmallInteger(), nullable=False),
        sa.Column("server_id", sa.String(length=36), nullable=False),
        sa.Column("server_secret_hash", sa.String(length=64), nullable=False),
        sa.Column("connection_password_hash", sa.String(length=256), nullable=True),
        sa.Column("enrollment_mode", sa.String(length=24), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_server_settings")),
        sa.UniqueConstraint("server_id", name=op.f("uq_server_settings_server_id")),
    )


def downgrade():
    op.drop_table("server_settings")
