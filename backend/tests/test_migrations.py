from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url

import app.models
from app.core.config import get_settings
from app.db.base import Base

BACKEND_ROOT = Path(__file__).resolve().parents[1]
SCRATCH_DATABASE = "cloudtrace_migration_check"


@pytest.fixture
def scratch_url():
    base = make_url(get_settings().database_url)
    admin = create_engine(base.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'DROP DATABASE IF EXISTS "{SCRATCH_DATABASE}" WITH (FORCE)'))
        connection.execute(text(f'CREATE DATABASE "{SCRATCH_DATABASE}"'))
    yield base.set(database=SCRATCH_DATABASE).render_as_string(hide_password=False)
    with admin.connect() as connection:
        connection.execute(text(f'DROP DATABASE IF EXISTS "{SCRATCH_DATABASE}" WITH (FORCE)'))
    admin.dispose()


def alembic_config(url: str) -> Config:
    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "alembic"))
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    config.attributes["configure_logger"] = False
    return config


def table_names(url: str) -> set[str]:
    engine = create_engine(url)
    try:
        return set(inspect(engine).get_table_names())
    finally:
        engine.dispose()


def test_migrations_build_the_full_schema_from_an_empty_database(scratch_url):
    command.upgrade(alembic_config(scratch_url), "head")
    assert table_names(scratch_url) == {*Base.metadata.tables, "alembic_version"}


def test_models_and_migrations_agree(scratch_url):
    command.upgrade(alembic_config(scratch_url), "head")
    engine = create_engine(scratch_url)
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(connection, opts={"compare_type": True})
            differences = compare_metadata(context, Base.metadata)
    finally:
        engine.dispose()
    assert differences == []


def test_migrations_can_be_reverted_and_reapplied(scratch_url):
    config = alembic_config(scratch_url)
    command.upgrade(config, "head")
    command.downgrade(config, "base")
    assert table_names(scratch_url) == {"alembic_version"}
    command.upgrade(config, "head")
    assert table_names(scratch_url) == {*Base.metadata.tables, "alembic_version"}