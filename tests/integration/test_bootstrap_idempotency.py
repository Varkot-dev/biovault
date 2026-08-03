"""Bootstrap and RLS installation against a live database.

`bootstrap()` runs on every container start, so idempotency is a correctness
requirement rather than a nicety: a second `docker compose up` must not
duplicate seed data or fail on already-existing policies.

These tests exercise the RLS installation code directly. Without them that
module shows near-zero coverage despite being the security-critical path that
builds tenant isolation — the code runs in production but is never asserted on.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, text

from biovault.db.rls import (
    TENANT_SCOPED_TABLES,
    apply_rls_policies,
    clear_tenant_context,
    set_tenant_context,
)

pytestmark = [pytest.mark.integration, pytest.mark.security]


@pytest.fixture
def owner_conn(live_settings):
    """A live owner connection, rolled back after each test."""
    engine = create_engine(live_settings.database_url(as_owner=True), future=True)
    conn = engine.connect()
    trans = conn.begin()
    try:
        yield conn
    finally:
        trans.rollback()
        conn.close()
        engine.dispose()


def test_apply_rls_policies_is_idempotent(owner_conn, live_settings) -> None:
    """Re-running must not error on existing roles or policies.

    Policies are dropped and recreated; the role creation is guarded by an
    existence check. Both paths run on every container boot.
    """
    apply_rls_policies(owner_conn, app_role=live_settings.app_db_user)
    apply_rls_policies(owner_conn, app_role=live_settings.app_db_user)

    installed = owner_conn.execute(
        text("SELECT tablename FROM pg_policies WHERE schemaname = 'public'")
    ).scalars().all()

    for table in TENANT_SCOPED_TABLES:
        assert table in installed


def test_reapplying_policies_leaves_exactly_one_policy_per_table(
    owner_conn, live_settings
) -> None:
    """Duplicate policies would OR together and could widen access.

    PostgreSQL combines multiple permissive policies with OR, so a second
    policy accumulating on re-run would loosen isolation rather than tighten
    it. DROP-then-CREATE prevents that.
    """
    apply_rls_policies(owner_conn, app_role=live_settings.app_db_user)
    apply_rls_policies(owner_conn, app_role=live_settings.app_db_user)

    for table in TENANT_SCOPED_TABLES:
        count = owner_conn.execute(
            text(
                "SELECT count(*) FROM pg_policies "
                "WHERE schemaname = 'public' AND tablename = :t"
            ).bindparams(t=table)
        ).scalar_one()
        assert count == 1, f"{table} has {count} policies; duplicates widen access"


def test_set_and_clear_tenant_context_round_trip(owner_conn) -> None:
    set_tenant_context(owner_conn, "lab-broad")
    assert (
        owner_conn.execute(
            text("SELECT current_setting('biovault.tenant_id', true)")
        ).scalar_one()
        == "lab-broad"
    )

    clear_tenant_context(owner_conn)
    assert owner_conn.execute(
        text("SELECT current_setting('biovault.tenant_id', true)")
    ).scalar_one() in (None, "")


def test_tenant_context_value_is_bound_not_interpolated(owner_conn) -> None:
    """A hostile tenant identifier must not be able to inject SQL.

    Tenant ids ultimately derive from token claims, so this is defence in
    depth rather than the primary control — but `set_config` binds the value,
    so the payload below is stored verbatim rather than executed.
    """
    hostile = "lab-broad'; DROP TABLE genomic_records; --"
    set_tenant_context(owner_conn, hostile)

    stored = owner_conn.execute(
        text("SELECT current_setting('biovault.tenant_id', true)")
    ).scalar_one()
    assert stored == hostile

    still_there = owner_conn.execute(
        text("SELECT count(*) FROM information_schema.tables WHERE table_name = 'genomic_records'")
    ).scalar_one()
    assert still_there == 1, "table was dropped; value was interpolated, not bound"


def test_seed_is_not_duplicated_on_second_bootstrap(live_settings) -> None:
    """The seed guard checks for existing tenants before inserting.

    A second `docker compose up` must not double every record.
    """
    from biovault.db.bootstrap import _seed

    engine = create_engine(live_settings.database_url(as_owner=True), future=True)
    with engine.connect() as conn:
        before = conn.execute(text("SELECT count(*) FROM genomic_records")).scalar_one()
    engine.dispose()

    _seed(live_settings)

    engine = create_engine(live_settings.database_url(as_owner=True), future=True)
    with engine.connect() as conn:
        after = conn.execute(text("SELECT count(*) FROM genomic_records")).scalar_one()
    engine.dispose()

    assert before == after, "re-running the seed duplicated records"


def test_app_role_password_can_be_set(owner_conn, live_settings) -> None:
    """ALTER ROLE cannot take bind parameters, so format() with %I/%L is used.

    Verifies the statement executes rather than erroring on quoting.
    """
    from biovault.db.rls import set_app_role_password

    set_app_role_password(
        owner_conn,
        app_role=live_settings.app_db_user,
        password=live_settings.app_db_password.get_secret_value(),
    )
    exists = owner_conn.execute(
        text("SELECT count(*) FROM pg_roles WHERE rolname = :r").bindparams(
            r=live_settings.app_db_user
        )
    ).scalar_one()
    assert exists == 1
