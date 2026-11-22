"""Add durable correlated activities and source event links.

Revision ID: a8c41d7e9f20
Revises: d4a7b92c1e60
Create Date: 2026-11-22
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql


revision = "a8c41d7e9f20"
down_revision = "d4a7b92c1e60"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "correlated_activities",
        sa.Column("id", sa.Uuid(as_uuid=True, native_uuid=False), nullable=False),
        sa.Column("agent_id", sa.Uuid(as_uuid=True, native_uuid=False), nullable=False),
        sa.Column("activity_type", sa.String(length=80), nullable=False),
        sa.Column("correlation_key", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=160), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("context", sa.JSON(), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["agent_id"], ["agents.id"],
            name="fk_correlated_activities_agent_id_agents",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_correlated_activities_agent_last_seen",
        "correlated_activities", ["agent_id", "last_seen_at"],
    )
    op.create_index(
        "ix_correlated_activities_last_seen",
        "correlated_activities", ["last_seen_at"],
    )
    op.create_index(
        "ix_correlated_activities_type_key_seen",
        "correlated_activities", ["activity_type", "correlation_key", "last_seen_at"],
    )
    op.create_table(
        "correlated_activity_events",
        sa.Column("id", sa.Uuid(as_uuid=True, native_uuid=False), nullable=False),
        sa.Column("activity_id", sa.Uuid(as_uuid=True, native_uuid=False), nullable=False),
        sa.Column("event_id", sa.Uuid(as_uuid=True, native_uuid=False), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["activity_id"], ["correlated_activities.id"],
            name="fk_correlated_activity_events_activity_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["event_id"], ["security_events.id"],
            name="fk_correlated_activity_events_event_id",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "activity_id", "event_id",
            name="uq_correlated_activity_events_pair",
        ),
    )
    op.create_index(
        "ix_correlated_activity_events_event",
        "correlated_activity_events", ["event_id"],
    )


def downgrade():
    op.drop_index("ix_correlated_activity_events_event", table_name="correlated_activity_events")
    op.drop_table("correlated_activity_events")
    op.drop_index("ix_correlated_activities_type_key_seen", table_name="correlated_activities")\n    op.drop_index("ix_correlated_activities_last_seen", table_name="correlated_activities")
    op.drop_index("ix_correlated_activities_agent_last_seen", table_name="correlated_activities")
    op.drop_table("correlated_activities")
