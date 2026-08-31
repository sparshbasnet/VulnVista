"""baseline: core tables (targets, scans, findings, evidence)

Revision ID: 20260813_0000
Revises:
Create Date: baseline

The core tables were historically created at runtime by
``Base.metadata.create_all`` rather than by a migration, so ``alembic upgrade
head`` could not provision a fresh database on its own. This baseline creates
them (and their enum types) so migrations are the single source of truth. It is
the first revision in the chain; ``20260814_0001`` now descends from it.

Enum types are created with ``checkfirst=True`` so this is safe to run against a
database that was previously provisioned by ``create_all`` (already-existing
types are left untouched). Databases that predate this migration are stamped at
a later revision, so they never run it.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "20260813_0000"
down_revision: str | None = None
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    scan_status = postgresql.ENUM(
        "QUEUED", "RUNNING", "COMPLETED", "PARTIAL", "FAILED", "CANCELLED", name="scan_status"
    )
    scan_status.create(op.get_bind(), checkfirst=True)
    validation_status = postgresql.ENUM(
        "NOT_DETECTED", "SUSPECTED", "CONFIRMED", "INCONCLUSIVE", "ERROR", name="validation_status"
    )
    validation_status.create(op.get_bind(), checkfirst=True)
    finding_status = postgresql.ENUM(
        "OPEN", "IN_PROGRESS", "REMEDIATED", "ACCEPTED_RISK", "FALSE_POSITIVE",
        name="finding_status",
    )
    finding_status.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "targets",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("target_type", sa.String(length=64), nullable=False),
        sa.Column("base_url", sa.String(length=512), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("environment", sa.String(length=64), nullable=False),
        sa.Column("is_allowed", sa.Boolean(), nullable=False),
        sa.Column("authorization_confirmed", sa.Boolean(), nullable=False),
        sa.Column("scan_config", sa.JSON(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_profile", sa.String(length=64), nullable=False),
        sa.Column(
            "status",
            postgresql.ENUM(
                "QUEUED", "RUNNING", "COMPLETED", "PARTIAL", "FAILED", "CANCELLED",
                name="scan_status", create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_seconds", sa.Float(), nullable=True),
        sa.Column("initiated_by", sa.String(length=255), nullable=True),
        sa.Column("error_summary", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("detector_id", sa.String(length=128), nullable=False),
        sa.Column("vulnerability_name", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.String(length=32), nullable=False),
        sa.Column(
            "validation_status",
            postgresql.ENUM(
                "NOT_DETECTED", "SUSPECTED", "CONFIRMED", "INCONCLUSIVE", "ERROR",
                name="validation_status", create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("affected_endpoint", sa.String(length=512), nullable=True),
        sa.Column("parameter", sa.String(length=255), nullable=True),
        sa.Column("evidence_summary", sa.Text(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("cwe", sa.String(length=32), nullable=True),
        sa.Column("cve", sa.String(length=32), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("owasp_category", sa.String(length=128), nullable=True),
        sa.Column(
            "finding_status",
            postgresql.ENUM(
                "OPEN", "IN_PROGRESS", "REMEDIATED", "ACCEPTED_RISK", "FALSE_POSITIVE",
                name="finding_status", create_type=False,
            ),
            nullable=False,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("evidence_type", sa.String(length=64), nullable=False),
        sa.Column("content", sa.JSON(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("evidence")
    op.drop_table("findings")
    op.drop_table("scans")
    op.drop_table("targets")
    postgresql.ENUM(name="finding_status").drop(op.get_bind(), checkfirst=True)
    postgresql.ENUM(name="validation_status").drop(op.get_bind(), checkfirst=True)
    postgresql.ENUM(name="scan_status").drop(op.get_bind(), checkfirst=True)
