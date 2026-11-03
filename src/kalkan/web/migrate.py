"""Schema migrations (Alembic) for the web app and the worker."""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Iterator
from typing import Any, Literal

from alembic import command
from alembic.autogenerate.api import AutogenContext
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Connection, Engine, inspect

from kalkan.web.db import UTCDateTime

log = logging.getLogger(__name__)

SCRIPT_LOCATION = "kalkan.web:migrations"
# Databases created by Phase 0's ``create_all`` match this revision exactly.
BASELINE_REVISION = "0001"


def render_item(type_: str, obj: Any, autogen_context: AutogenContext) -> str | Literal[False]:
    """Write portable column types into migration files instead of our TypeDecorator."""
    if type_ == "type" and isinstance(obj, UTCDateTime):
        return "sa.DateTime(timezone=True)"
    return False


def alembic_config(connection: Connection | None = None) -> Config:
    config = Config()
    config.set_main_option("script_location", SCRIPT_LOCATION)
    if connection is not None:
        config.attributes["connection"] = connection
    return config


def head_revision() -> str:
    head = ScriptDirectory.from_config(alembic_config()).get_current_head()
    if head is None:  # pragma: no cover - the package always ships revisions
        raise RuntimeError("no migration revisions found")
    return head


def current_revision(engine: Engine) -> str | None:
    with engine.connect() as connection:
        return MigrationContext.configure(connection).get_current_revision()


def _created_without_alembic(connection: Connection) -> bool:
    tables = set(inspect(connection).get_table_names())
    return "users" in tables and "alembic_version" not in tables


@contextlib.contextmanager
def _migration_connection(engine: Engine) -> Iterator[Connection]:
    """A connection in a transaction, with SQLite foreign keys switched off.

    SQLite cannot drop or alter columns, so Alembic "batch" migrations copy the table
    and DROP the original. With foreign keys enforced, that DROP first deletes every row
    and ON DELETE CASCADE wipes the child tables (e.g. all scans of every domain).
    The pragma only takes effect outside a transaction, hence the explicit commit.
    """
    with engine.connect() as connection:
        sqlite = connection.dialect.name == "sqlite"
        if sqlite:
            connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
            connection.commit()
        try:
            with connection.begin():
                yield connection
        finally:
            if sqlite:
                connection.exec_driver_sql("PRAGMA foreign_keys=ON")
                connection.commit()


def upgrade_database(engine: Engine, revision: str = "head") -> None:
    with _migration_connection(engine) as connection:
        config = alembic_config(connection)
        if _created_without_alembic(connection):
            log.warning("database predates migrations; stamping revision %s", BASELINE_REVISION)
            command.stamp(config, BASELINE_REVISION)
        command.upgrade(config, revision)


def downgrade_database(engine: Engine, revision: str) -> None:
    with _migration_connection(engine) as connection:
        command.downgrade(alembic_config(connection), revision)


class SchemaOutdatedError(RuntimeError):
    pass


def ensure_current(engine: Engine) -> None:
    """Refuse to start against a database that has not been migrated."""
    current, head = current_revision(engine), head_revision()
    if current != head:
        raise SchemaOutdatedError(
            f"database schema is at {current or 'nothing'}, expected {head}: run `kalkan migrate`"
        )
