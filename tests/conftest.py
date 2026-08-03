"""Shared pytest fixtures.

Integration tests need a live PostgreSQL. They are skipped rather than failed
when one is unavailable, so the unit suite stays runnable without Docker —
but CI runs with a database present, so the skip never hides a real failure
there. `test_integration_tests_actually_ran` in the CI job guards that.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator

import pytest
from sqlalchemy import Connection, Engine, create_engine, text
from sqlalchemy.orm import Session


def _database_available(url: str) -> bool:
    try:
        engine = create_engine(url, pool_pre_ping=True)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
    except Exception:
        return False
    return True


def _app_url() -> str:
    user = os.environ.get("BIOVAULT_APP_DB_USER", "biovault_app")
    password = os.environ.get("BIOVAULT_APP_DB_PASSWORD", "")
    host = os.environ.get("POSTGRES_HOST", "localhost")
    port = os.environ.get("POSTGRES_PORT", "5432")
    database = os.environ.get("POSTGRES_DB", "biovault")
    return f"postgresql+psycopg://{user}:{password}@{host}:{port}/{database}"


@pytest.fixture(scope="session")
def app_engine_fixture() -> Iterator[Engine]:
    """Engine bound to the least-privilege role, so RLS applies."""
    url = _app_url()
    if not _database_available(url):
        pytest.skip("PostgreSQL not reachable as the application role")
    engine = create_engine(url, pool_pre_ping=True, future=True)
    yield engine
    engine.dispose()


@pytest.fixture
def app_connection(app_engine_fixture: Engine) -> Iterator[Connection]:
    """A connection as the app role, rolled back after each test.

    Rollback rather than commit keeps tests independent and means probe rows
    inserted by a test do not persist into the next one.
    """
    conn = app_engine_fixture.connect()
    conn.begin()
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


def _owner_url() -> str:
    user = os.environ.get("POSTGRES_USER", "biovault_owner")
    password = os.environ.get("POSTGRES_PASSWORD", "")
    host = os.environ.get("POSTGRES_HOST", "localhost")
    port = os.environ.get("POSTGRES_PORT", "5432")
    database = os.environ.get("POSTGRES_DB", "biovault")
    return f"postgresql+psycopg://{user}:{password}@{host}:{port}/{database}"


@pytest.fixture(scope="session")
def owner_engine_fixture() -> Iterator[Engine]:
    """Engine bound to the schema owner.

    Used only for tables that are not tenant-filtered (refresh tokens,
    authorization codes) and for setup that legitimately spans tenants.
    Never use this to assert tenant isolation — the owner bypasses nothing
    here only because RLS is FORCEd, and relying on that would make the
    isolation tests depend on a setting rather than on policy.
    """
    url = _owner_url()
    if not _database_available(url):
        pytest.skip("PostgreSQL not reachable as the owner role")
    engine = create_engine(url, pool_pre_ping=True, future=True)
    yield engine
    engine.dispose()


@pytest.fixture
def owner_session(owner_engine_fixture: Engine) -> Iterator[Session]:
    """An owner-role ORM session, rolled back after each test."""
    from sqlalchemy.orm import Session as OrmSession

    conn = owner_engine_fixture.connect()
    trans = conn.begin()
    session = OrmSession(bind=conn, future=True)
    try:
        yield session
    finally:
        session.close()
        trans.rollback()
        conn.close()


@pytest.fixture
def set_tenant(app_connection: Connection) -> Callable[[str], None]:
    """Bind the current transaction to a tenant, as the API does per request."""

    def _set(tenant_id: str) -> None:
        app_connection.execute(
            text("SELECT set_config('biovault.tenant_id', :t, true)").bindparams(t=tenant_id)
        )

    return _set


@pytest.fixture
def clear_tenant(app_connection: Connection) -> Callable[[], None]:
    """Unset tenant context, which must match zero rows."""

    def _clear() -> None:
        app_connection.execute(
            text("SELECT set_config('biovault.tenant_id', '', true)")
        )

    return _clear
