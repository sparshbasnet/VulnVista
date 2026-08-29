"""add discoveries table and scan path-scope columns

Revision ID: 20260826_0003
Revises: 20260824_0002
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "20260826_0003"
down_revision: str | None = "20260824_0002"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    discovery_status = postgresql.ENUM(
        "QUEUED", "RUNNING", "COMPLETED", "FAILED", name="discovery_status"
    )
    discovery_status.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "discoveries",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "status",
            postgresql.ENUM(
                "QUEUED", "RUNNING", "COMPLETED", "FAILED",
                name="discovery_status", create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("initiated_by", sa.Text(), nullable=True),
        sa.Column("error_summary", sa.Text(), nullable=True),
        sa.Column("page_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("paths", sa.JSON(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    op.add_column("scans", sa.Column("in_scope_paths", sa.JSON(), nullable=True))
    op.add_column("scans", sa.Column("out_of_scope_paths", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "out_of_scope_paths")
    op.drop_column("scans", "in_scope_paths")
    op.drop_table("discoveries")
    postgresql.ENUM(name="discovery_status").drop(op.get_bind(), checkfirst=True)
