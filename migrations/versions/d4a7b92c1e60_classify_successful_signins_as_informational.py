"""Reclassify historical Windows successful logons as informational.

Revision ID: d4a7b92c1e60
Revises: b7e3a91d5c42
Create Date: 2026-11-19
"""
from alembic import op
import sqlalchemy as sa


revision = "d4a7b92c1e60"
down_revision = "b7e3a91d5c42"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        sa.text(
            """
            UPDATE security_events
            SET severity = 0
            WHERE source = 'Windows Security'
              AND category = 'authentication'
              AND event_type = 'login.success'
              AND event_code = '4624'
            """
        )
    )


def downgrade():
    op.execute(
        sa.text(
            """
            UPDATE security_events
            SET severity = 2
            WHERE source = 'Windows Security'
              AND category = 'authentication'
              AND event_type = 'login.success'
              AND event_code = '4624'
              AND severity = 0
            """
        )
    )
