"""drop the unique constraint on targets.base_url

Revision ID: 20260902_0005
Revises: 20260831_0004

`uq_targets_base_url` was added by the lost revision reconciled in
20260831_0004. It contradicts how a target is identified: `POST /targets` treats
the same URL with a different `scan_config` — an authenticated context versus an
anonymous one — or in a different `environment` as a genuinely separate target
(see `_find_equivalent_target` in app/api/v1/targets.py, and the reasoning in
scripts/dedupe_targets.py). With the constraint in place those legitimate
registrations fail on an IntegrityError instead of creating a record.

Uniqueness is enforced in the application against the *normalised* endpoint
identity, which is not a stored column and so cannot be a column constraint.

Guarded with IF EXISTS so it is also a no-op on databases that never received
the lost revision.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20260902_0005"
down_revision: str | None = "20260831_0004"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE targets DROP CONSTRAINT IF EXISTS uq_targets_base_url")


def downgrade() -> None:
    """Intentionally not reversible.

    Re-adding the constraint fails on any database holding two targets that share
    a base_url, which the application permits by design. Recreate it by hand if a
    downgrade ever genuinely needs it.
    """
