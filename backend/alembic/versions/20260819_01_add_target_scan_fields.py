"""Add target authorization and detector configuration fields.

Revision ID: 20260819_01
Revises: 20260817_01, 20260814_0001
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "20260819_01"
down_revision: tuple[str, str] = ("20260817_01", "20260814_0001")
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "targets",
        sa.Column(
            "authorization_confirmed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.alter_column("targets", "authorization_confirmed", server_default=None)
    op.add_column("targets", sa.Column("scan_config", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("targets", "scan_config")
    op.drop_column("targets", "authorization_confirmed")
