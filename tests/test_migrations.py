from __future__ import annotations

from collections.abc import Iterator

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import Engine, inspect, text

from kalkan.web.db import Base, make_engine
from kalkan.web.migrate import (
    SchemaOutdatedError,
    alembic_config,
    current_revision,
    downgrade_database,
    ensure_current,
    head_revision,
    render_item,
    upgrade_database,
)

APP_TABLES = {
    "users",
    "domains",
    "scans",
    "api_tokens",
    "organizations",
    "memberships",
    "invitations",
}


@pytest.fixture
def engine(database_url: str) -> Iterator[Engine]:
    engine = make_engine(database_url)
    yield engine
    engine.dispose()


def tables(engine: Engine) -> set[str]:
    return set(inspect(engine).get_table_names())


def test_upgrade_creates_the_schema(engine: Engine) -> None:
    upgrade_database(engine)
    assert APP_TABLES | {"alembic_version"} <= tables(engine)
    assert current_revision(engine) == head_revision()
    ensure_current(engine)


def test_migrations_match_the_models(engine: Engine) -> None:
    """Fails when a model changes without a new migration (autogenerate would emit ops)."""
    upgrade_database(engine)
    with engine.connect() as connection:
        context = MigrationContext.configure(
            connection, opts={"compare_type": True, "render_item": render_item}
        )
        assert compare_metadata(context, Base.metadata) == []


def test_downgrade_and_upgrade_again(engine: Engine) -> None:
    upgrade_database(engine)
    downgrade_database(engine, "0001")
    assert "api_tokens" not in tables(engine)
    assert "email_verified_at" not in {c["name"] for c in inspect(engine).get_columns("users")}
    downgrade_database(engine, "base")
    assert not tables(engine) & APP_TABLES
    upgrade_database(engine)
    assert current_revision(engine) == head_revision()


def test_existing_users_count_as_verified(engine: Engine) -> None:
    upgrade_database(engine, "0001")
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO users (email, password_hash, created_at) "
                "VALUES ('eski@example.com', 'x', CURRENT_TIMESTAMP)"
            )
        )
    upgrade_database(engine)
    with engine.connect() as connection:
        row = connection.execute(text("SELECT email_verified_at, session_version FROM users")).one()
    assert row.email_verified_at is not None
    assert row.session_version == 0


def test_database_created_before_migrations_is_adopted(engine: Engine) -> None:
    """Phase 0 used create_all: such a database gets stamped and upgraded, not recreated."""
    upgrade_database(engine, "0001")
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE alembic_version"))
        connection.execute(
            text(
                "INSERT INTO users (email, password_hash, created_at) "
                "VALUES ('faz0@example.com', 'x', CURRENT_TIMESTAMP)"
            )
        )
    upgrade_database(engine)
    assert current_revision(engine) == head_revision()
    with engine.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM users")).scalar() == 1


def test_ensure_current_rejects_unmigrated_database(engine: Engine) -> None:
    with pytest.raises(SchemaOutdatedError, match="kalkan migrate"):
        ensure_current(engine)
    upgrade_database(engine, "0001")
    with pytest.raises(SchemaOutdatedError, match="0001"):
        ensure_current(engine)


def test_offline_sql_generation(capsys: pytest.CaptureFixture[str]) -> None:
    config = alembic_config()
    config.set_main_option("sqlalchemy.url", "postgresql://")
    command.upgrade(config, "head", sql=True)
    sql = capsys.readouterr().out
    assert "CREATE TABLE users" in sql
    assert "CREATE TABLE api_tokens" in sql
    assert "DEFAULT true" in sql


def test_users_get_personal_organizations(engine: Engine) -> None:
    """0003 moves each user's domains and tokens into a personal organization."""
    upgrade_database(engine, "0002")
    with engine.begin() as connection:
        for user_id, email in ((1, "a@example.com"), (2, "b@example.com")):
            connection.execute(
                text(
                    "INSERT INTO users (id, email, password_hash, created_at, session_version) "
                    "VALUES (:id, :email, 'x', CURRENT_TIMESTAMP, 0)"
                ),
                {"id": user_id, "email": email},
            )
        connection.execute(
            text(
                "INSERT INTO domains (user_id, hostname, verification_token, created_at, "
                "scan_interval_days, notify_email) VALUES "
                "(1, 'a.example.com', 't', CURRENT_TIMESTAMP, 0, true), "
                "(2, 'a.example.com', 't', CURRENT_TIMESTAMP, 0, true)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO api_tokens (user_id, name, token_hash, prefix, created_at) "
                "VALUES (2, 'ci', 'h', 'klk_x', CURRENT_TIMESTAMP)"
            )
        )
        # Child rows must survive the table rebuilds SQLite needs (no cascading deletes).
        connection.execute(
            text(
                'INSERT INTO scans (domain_id, status, created_at, "trigger") '
                "VALUES (1, 'done', CURRENT_TIMESTAMP, 'manual')"
            )
        )
    upgrade_database(engine)
    with engine.connect() as connection:
        orgs = connection.execute(
            text("SELECT id, name, plan FROM organizations ORDER BY id")
        ).all()
        assert [(o.name, o.plan) for o in orgs] == [
            ("a@example.com", "free"),
            ("b@example.com", "free"),
        ]
        owners = connection.execute(
            text("SELECT organization_id, user_id, role FROM memberships ORDER BY id")
        ).all()
        assert [tuple(r) for r in owners] == [(orgs[0].id, 1, "owner"), (orgs[1].id, 2, "owner")]
        domains = (
            connection.execute(text("SELECT organization_id FROM domains ORDER BY id"))
            .scalars()
            .all()
        )
        assert domains == [orgs[0].id, orgs[1].id]
        token_org = connection.execute(text("SELECT organization_id FROM api_tokens")).scalar()
        assert token_org == orgs[1].id
        assert connection.execute(text("SELECT count(*) FROM scans")).scalar() == 1
    # and back: domains return to the organization owner, scans stay
    downgrade_database(engine, "0002")
    with engine.connect() as connection:
        assert connection.execute(
            text("SELECT user_id FROM domains ORDER BY id")
        ).scalars().all() == [1, 2]
        assert connection.execute(text("SELECT count(*) FROM scans")).scalar() == 1


def test_foreign_keys_are_enforced_again_after_migrating(engine: Engine) -> None:
    upgrade_database(engine)
    if engine.dialect.name != "sqlite":
        pytest.skip("SQLite-specific pragma")
    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
