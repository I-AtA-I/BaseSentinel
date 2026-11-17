
"""Name inventory foreign keys

Revision ID: 972ccdcd9499
Revises: 62e559a83bf6
"""

from alembic import op
import sqlalchemy as sa


revision = "972ccdcd9499"
down_revision = "62e559a83bf6"
branch_labels = None
depends_on = None


def _ensure_foreign_key_name(
    table_name: str,
    local_column: str,
    referred_table: str,
    referred_column: str,
    target_name: str,
) -> None:
    """Ensure a foreign key has the expected name."""

    connection = op.get_bind()
    inspector = sa.inspect(connection)

    foreign_keys = inspector.get_foreign_keys(table_name)

    matching = [
        fk for fk in foreign_keys
        if fk.get("constrained_columns") == [local_column]
        and fk.get("referred_table") == referred_table
        and fk.get("referred_columns") == [referred_column]
    ]

    if len(matching) > 1:
        raise RuntimeError(
            f"Multiple matching foreign keys found on {table_name}."
        )

    if matching:
        foreign_key = matching[0]
        current_name = foreign_key.get("name")

        if current_name == target_name:
            return

        if not current_name:
            raise RuntimeError(
                f"Cannot identify foreign key on {table_name}."
            )

        options = foreign_key.get("options") or {}

        ondelete = options.get("ondelete") or "RESTRICT"
        onupdate = options.get("onupdate") or "RESTRICT"

        op.drop_constraint(
            current_name,
            table_name,
            type_="foreignkey",
        )

    else:
        # Recovery path if a previous migration attempt
        # dropped the constraint but failed before recreating it.
        ondelete = "RESTRICT"
        onupdate = "RESTRICT"

    op.create_foreign_key(
        target_name,
        table_name,
        referred_table,
        [local_column],
        [referred_column],
        ondelete=ondelete,
        onupdate=onupdate,
    )


def upgrade():
    _ensure_foreign_key_name(
        table_name="asset_addresses",
        local_column="interface_id",
        referred_table="asset_interfaces",
        referred_column="id",
        target_name="fk_asset_addresses_interface_id_asset_interfaces",
    )

    _ensure_foreign_key_name(
        table_name="asset_interfaces",
        local_column="asset_id",
        referred_table="assets",
        referred_column="id",
        target_name="fk_asset_interfaces_asset_id_assets",
    )


def downgrade():
    _ensure_foreign_key_name(
        table_name="asset_interfaces",
        local_column="asset_id",
        referred_table="assets",
        referred_column="id",
        target_name="1",
    )

    _ensure_foreign_key_name(
        table_name="asset_addresses",
        local_column="interface_id",
        referred_table="asset_interfaces",
        referred_column="id",
        target_name="1",
    )
