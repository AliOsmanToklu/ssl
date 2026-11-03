"""accounts, API tokens and scheduled scans (Phase 1)

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "api_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("prefix", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index("ix_api_tokens_user_id", "api_tokens", ["user_id"])

    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(
            sa.Column("session_version", sa.Integer(), server_default="0", nullable=False)
        )
    # Accounts created before e-mail verification existed keep working.
    op.execute("UPDATE users SET email_verified_at = created_at")

    with op.batch_alter_table("domains") as batch:
        batch.add_column(
            sa.Column("scan_interval_days", sa.Integer(), server_default="0", nullable=False)
        )
        batch.add_column(sa.Column("next_scan_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(
            sa.Column("notify_email", sa.Boolean(), server_default=sa.true(), nullable=False)
        )
    op.create_index("ix_domains_next_scan_at", "domains", ["next_scan_at"])

    with op.batch_alter_table("scans") as batch:
        batch.add_column(
            sa.Column(
                "trigger",
                sa.Enum(
                    "manual", "scheduled", "api", name="scantrigger", native_enum=False, length=16
                ),
                server_default="manual",
                nullable=False,
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("scans") as batch:
        batch.drop_column("trigger")
    op.drop_index("ix_domains_next_scan_at", table_name="domains")
    with op.batch_alter_table("domains") as batch:
        batch.drop_column("notify_email")
        batch.drop_column("next_scan_at")
        batch.drop_column("scan_interval_days")
    with op.batch_alter_table("users") as batch:
        batch.drop_column("session_version")
        batch.drop_column("email_verified_at")
    op.drop_table("api_tokens")
