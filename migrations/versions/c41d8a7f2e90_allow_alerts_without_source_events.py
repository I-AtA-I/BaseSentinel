"""Allow alerts to remain after source events are flushed.

Revision ID: c41d8a7f2e90
Revises: d4a7b92c1e60
Create Date: 2026-11-21
"""

from alembic import op
import sqlalchemy as sa


revision = "c41d8a7f2e90"
down_revision = "d4a7b92c1e60"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("alerts", schema=None) as batch_op:
        batch_op.alter_column(
            "source_event_id",
            existing_type=sa.Uuid(native_uuid=False),
            nullable=True,
        )


def downgrade():
    # Alerts detached by an event flush cannot regain their original source.
    op.execute("DELETE FROM alerts WHERE source_event_id IS NULL")
    with op.batch_alter_table("alerts", schema=None) as batch_op:
        batch_op.alter_column(
            "source_event_id",
            existing_type=sa.Uuid(native_uuid=False),
            nullable=False,
        )
