"""Add the crawler page count to scans.

Revision ID: 20260817_01
Revises:
Create Date: 2026-08-17
"""

revision = "20260817_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    from alembic import op

    op.execute(
        "ALTER TABLE scans ADD COLUMN IF NOT EXISTS pages_scanned INTEGER NOT NULL DEFAULT 0"
    )


def downgrade() -> None:
    from alembic import op

    op.drop_column("scans", "pages_scanned")
