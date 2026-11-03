"""organizations, memberships, invitations; language and onboarding fields (Phase 3)

Every existing user gets a personal organization (as its owner) that takes over the
user's domains and API tokens, so nothing changes for them after the upgrade.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _role() -> sa.Enum:
    return sa.Enum("owner", "admin", "member", name="role", native_enum=False, length=16)


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column(
            "plan",
            sa.Enum("free", "pro", "agency", name="plan", native_enum=False, length=16),
            server_default="free",
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "memberships",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("role", _role(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "user_id", name="uq_membership"),
    )
    op.create_index("ix_memberships_organization_id", "memberships", ["organization_id"])
    op.create_index("ix_memberships_user_id", "memberships", ["user_id"])
    op.create_table(
        "invitations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("role", _role(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("invited_by_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["invited_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index("ix_invitations_organization_id", "invitations", ["organization_id"])

    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("locale", sa.String(length=8), nullable=True))
        batch.add_column(
            sa.Column("onboarding_reminded_at", sa.DateTime(timezone=True), nullable=True)
        )
    with op.batch_alter_table("scans") as batch:
        batch.add_column(sa.Column("error_detail", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("requested_by_id", sa.Integer(), nullable=True))
        batch.create_foreign_key(
            "fk_scans_requested_by_id_users",
            "users",
            ["requested_by_id"],
            ["id"],
            ondelete="SET NULL",
        )
    with op.batch_alter_table("domains") as batch:
        batch.add_column(sa.Column("organization_id", sa.Integer(), nullable=True))
    with op.batch_alter_table("api_tokens") as batch:
        batch.add_column(sa.Column("organization_id", sa.Integer(), nullable=True))

    # Data: one personal organization per existing user, named after the e-mail address
    # (unique), which is also how the rows are matched up again. Plain SQL so that it runs
    # the same on SQLite and PostgreSQL, and in offline (--sql) mode.
    op.execute(
        "INSERT INTO organizations (name, plan, created_at) "
        "SELECT substr(email, 1, 100), 'free', created_at FROM users ORDER BY id"
    )
    op.execute(
        "INSERT INTO memberships (organization_id, user_id, role, created_at) "
        "SELECT o.id, u.id, 'owner', u.created_at FROM users u "
        "JOIN organizations o ON o.name = substr(u.email, 1, 100)"
    )
    for table in ("domains", "api_tokens"):
        op.execute(
            f"UPDATE {table} SET organization_id = ("  # noqa: S608 - fixed table names
            "SELECT m.organization_id FROM memberships m "
            f"WHERE m.user_id = {table}.user_id AND m.role = 'owner')"
        )

    with op.batch_alter_table("domains") as batch:
        batch.drop_constraint("uq_domain_per_user", type_="unique")
        batch.drop_index("ix_domains_user_id")
        batch.drop_column("user_id")
        batch.alter_column("organization_id", existing_type=sa.Integer(), nullable=False)
        batch.create_foreign_key(
            "fk_domains_organization_id_organizations",
            "organizations",
            ["organization_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch.create_unique_constraint(
            "uq_domain_per_organization", ["organization_id", "hostname"]
        )
        batch.create_index("ix_domains_organization_id", ["organization_id"])
    with op.batch_alter_table("api_tokens") as batch:
        batch.alter_column("organization_id", existing_type=sa.Integer(), nullable=False)
        batch.create_foreign_key(
            "fk_api_tokens_organization_id_organizations",
            "organizations",
            ["organization_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch.create_index("ix_api_tokens_organization_id", ["organization_id"])


def downgrade() -> None:
    with op.batch_alter_table("domains") as batch:
        batch.add_column(sa.Column("user_id", sa.Integer(), nullable=True))
    # Give each domain back to the (first) owner of its organization.
    op.execute(
        """
        UPDATE domains SET user_id = (
            SELECT m.user_id FROM memberships m
            WHERE m.organization_id = domains.organization_id AND m.role = 'owner'
            ORDER BY m.id LIMIT 1
        )
        """
    )
    op.execute("DELETE FROM domains WHERE user_id IS NULL")
    with op.batch_alter_table("domains") as batch:
        batch.drop_index("ix_domains_organization_id")
        batch.drop_constraint("uq_domain_per_organization", type_="unique")
        batch.drop_constraint("fk_domains_organization_id_organizations", type_="foreignkey")
        batch.drop_column("organization_id")
        batch.alter_column("user_id", existing_type=sa.Integer(), nullable=False)
        batch.create_foreign_key(
            "fk_domains_user_id_users", "users", ["user_id"], ["id"], ondelete="CASCADE"
        )
        batch.create_unique_constraint("uq_domain_per_user", ["user_id", "hostname"])
        batch.create_index("ix_domains_user_id", ["user_id"])
    with op.batch_alter_table("api_tokens") as batch:
        batch.drop_index("ix_api_tokens_organization_id")
        batch.drop_constraint("fk_api_tokens_organization_id_organizations", type_="foreignkey")
        batch.drop_column("organization_id")
    with op.batch_alter_table("scans") as batch:
        batch.drop_constraint("fk_scans_requested_by_id_users", type_="foreignkey")
        batch.drop_column("requested_by_id")
        batch.drop_column("error_detail")
    with op.batch_alter_table("users") as batch:
        batch.drop_column("onboarding_reminded_at")
        batch.drop_column("locale")
    op.drop_table("invitations")
    op.drop_table("memberships")
    op.drop_table("organizations")
