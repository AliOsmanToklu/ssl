"""Alembic environment.

Applications call :func:`kalkan.web.migrate.upgrade_database`, which hands over an
open connection via ``config.attributes["connection"]``. The ``alembic`` CLI (for
``revision --autogenerate``) falls back to ``KALKAN_DATABASE_URL``.
"""

from __future__ import annotations

from alembic import context
from sqlalchemy import Connection

from kalkan.web import models  # noqa: F401 - registers the tables on Base.metadata
from kalkan.web.config import Settings
from kalkan.web.db import Base, make_engine
from kalkan.web.migrate import render_item

config = context.config
target_metadata = Base.metadata


def _configure(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=connection.dialect.name == "sqlite",  # SQLite cannot ALTER much
        compare_type=True,
        render_item=render_item,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        _configure(connection)
        return
    url = config.get_main_option("sqlalchemy.url") or Settings().database_url
    engine = make_engine(url)
    try:
        with engine.connect() as conn:
            _configure(conn)
            conn.commit()
    finally:
        engine.dispose()


def run_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url") or Settings().database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        render_item=render_item,
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_offline()
else:
    run_online()
