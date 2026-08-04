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


def test_reapplying_policies_does_not_accumulate_duplicates(
    owner_conn, live_settings
) -> None:
    """Duplicate policies would OR together and could widen access.

    PostgreSQL combines multiple *permissive* policies with OR, so a policy
    accumulating on each re-run would progressively loosen isolation rather
    than tighten it — and `bootstrap()` runs on every container start.
    DROP-then-CREATE prevents that.

    `users` carries two policies by design: tenant isolation plus the narrow
    pre-authentication identity lookup. That pair is intentional and its blast
    radius is asserted in `tests/security/test_auth_lookup_policy.py`. Every
    other table must carry exactly one.
    """
    expected = {table: 1 for table in TENANT_SCOPED_TABLES}
    # Two tables carry a deliberate second policy, each a narrow cross-tenant
    # SELECT exception. Both are bounded by dedicated tests.
    expected["users"] = 2  # tenant isolation + pre-auth identity lookup
    expected["consortium_participation"] = 2  # tenant isolation + roster read

    apply_rls_policies(owner_conn, app_role=live_settings.app_db_user)
    apply_rls_policies(owner_conn, app_role=live_settings.app_db_user)
    apply_rls_policies(owner_conn, app_role=live_settings.app_db_user)

    for table, want in expected.items():
        count = owner_conn.execute(
            text(
                "SELECT count(*) FROM pg_policies "
                "WHERE schemaname = 'public' AND tablename = :t"
            ).bindparams(t=table)
        ).scalar_one()
        assert count == want, (
            f"{table} has {count} policies, expected {want}; "
            "duplicates OR together and widen access"
        )


def test_only_known_tables_carry_an_extra_policy(owner_conn, live_settings) -> None:
    """Guards against a future exception being added without scrutiny.

    Any second permissive policy on a tenant-scoped table widens access by
    construction. PostgreSQL ORs permissive policies together, so an extra one
    can only loosen isolation, never tighten it. This test fails if one appears
    on any table not on the allowlist below, forcing the author to justify it
    rather than have it merge unnoticed.

    The two that are allowed:
      users                     -- pre-auth identity lookup; without it login
                                   cannot bootstrap, since a user's tenant is
                                   a property of the user
      consortium_participation  -- reading the roster of participating labs,
                                   which inherently spans tenants
    Both are SELECT-only and both have a dedicated test bounding their reach.
    """
    allowed = ["consortium_participation", "users"]
    apply_rls_policies(owner_conn, app_role=live_settings.app_db_user)

    multi_policy = [
        table
        for table in TENANT_SCOPED_TABLES
        if owner_conn.execute(
            text(
                "SELECT count(*) FROM pg_policies "
                "WHERE schemaname = 'public' AND tablename = :t"
            ).bindparams(t=table)
        ).scalar_one()
        > 1
    ]
    assert sorted(multi_policy) == allowed, (
        f"unexpected tables with multiple permissive policies: "
        f"{sorted(set(multi_policy) - set(allowed))}"
    )


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
