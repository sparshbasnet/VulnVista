"""placeholder for a revision that was applied but never committed

Revision ID: 20260831_0004
Revises: 20260826_0003

A migration with this id was applied to the shared (Neon) database on
2026-08-31 but its file never reached the repository — `git log -S 20260831_0004`
finds nothing. From then on every container start failed with:

    Can't locate revision identified by '20260831_0004'

because Alembic cannot walk a history whose head it has no file for. This file
restores that link so `alembic upgrade head` runs again.

It is deliberately empty. The schema change the lost revision actually made was
`UNIQUE (base_url)` on `targets` (still present in the database as
`uq_targets_base_url`, and absent from `app/models/target.py`), which contradicts
how target identity works — see 20260902_0005, which removes it. Re-creating that
constraint here would break upgrades on any database that still holds duplicate
targets from before reuse-or-create existed, which is exactly the state
`scripts/dedupe_targets.py` was written to clean up.
"""

from collections.abc import Sequence

revision: str = "20260831_0004"
down_revision: str | None = "20260826_0003"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    """No-op: this revision exists only to make the history resolvable."""


def downgrade() -> None:
    """No-op: nothing was applied."""
