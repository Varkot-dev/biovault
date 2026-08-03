"""Tenant isolation at the PostgreSQL layer, independent of application code.

These tests connect to the database directly as the least-privilege runtime
role and issue raw SQL. No FastAPI, no `decide()`, no ORM-level filtering is
involved. If the application-layer policy were deleted entirely, every test in
this file would still have to pass.

That independence is the whole point: it is what makes "defense in depth" a
verifiable claim rather than an adjective.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text

from biovault.db.rls import TENANT_SCOPED_TABLES

pytestmark = [pytest.mark.security, pytest.mark.rls, pytest.mark.integration]

BROAD = "lab-broad"
SANGER = "lab-sanger"
RIKEN = "lab-riken"
ALL_TENANTS = (BROAD, SANGER, RIKEN)


def test_app_role_is_not_superuser_and_cannot_bypass_rls(app_connection) -> None:
    """Preconditions without which every other test here is meaningless.

    PostgreSQL exempts superusers and roles holding BYPASSRLS from all
    policies. If the app role held either attribute, the isolation tests below
    would pass only because the application layer happened to filter — and the
    database layer would be inert.
    """
    row = app_connection.execute(
        text(
            "SELECT rolsuper, rolbypassrls FROM pg_roles "
            "WHERE rolname = current_user"
        )
    ).one()
    assert row.rolsuper is False, "app role must not be a superuser"
    assert row.rolbypassrls is False, "app role must not hold BYPASSRLS"


@pytest.mark.parametrize("table", TENANT_SCOPED_TABLES)
def test_rls_is_enabled_and_forced_on_every_tenant_scoped_table(
    app_connection, table: str
) -> None:
    """ENABLE alone still exempts the table owner; FORCE closes that gap."""
    row = app_connection.execute(
        text(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
            "WHERE relname = :t"
        ).bindparams(t=table)
    ).one()
    assert row.relrowsecurity is True, f"RLS not enabled on {table}"
    assert row.relforcerowsecurity is True, f"RLS not forced on {table}"


def test_tenant_sees_only_its_own_records(app_connection, set_tenant) -> None:
    set_tenant(BROAD)
    rows = app_connection.execute(
        text("SELECT DISTINCT tenant_id FROM genomic_records")
    ).scalars().all()
    assert rows == [BROAD]


@pytest.mark.parametrize(("home", "foreign"), [
    (BROAD, SANGER), (BROAD, RIKEN),
    (SANGER, BROAD), (SANGER, RIKEN),
    (RIKEN, BROAD), (RIKEN, SANGER),
])
def test_explicit_cross_tenant_query_returns_nothing(
    app_connection, set_tenant, home: str, foreign: str
) -> None:
    """An explicit WHERE on another tenant cannot defeat the policy.

    This is the direct form of the attack: the caller knows the other lab's
    identifier and asks for it by name.
    """
    set_tenant(home)
    count = app_connection.execute(
        text("SELECT count(*) FROM genomic_records WHERE tenant_id = :t").bindparams(
            t=foreign
        )
    ).scalar_one()
    assert count == 0, f"{home} could see {foreign} rows"


@pytest.mark.parametrize("table", TENANT_SCOPED_TABLES)
def test_no_rows_visible_without_tenant_context(app_connection, clear_tenant, table: str) -> None:
    """Unset tenant context must fail closed.

    `current_setting(..., true)` yields NULL when unset, and `tenant_id = NULL`
    is NULL rather than TRUE, so the policy denies. A policy written without
    the missing-ok flag would raise instead, which callers tend to catch and
    ignore — failing open.
    """
    clear_tenant()
    # `table` is parametrized from TENANT_SCOPED_TABLES, a module constant.
    # Table names cannot be bound parameters in SQL, so interpolation is the
    # only option here; the assertion below guards the input is one of ours.
    assert table in TENANT_SCOPED_TABLES
    count = app_connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()  # noqa: S608
    assert count == 0, f"{table} leaked rows with no tenant context"


def test_cross_tenant_insert_is_rejected(app_connection, set_tenant) -> None:
    """WITH CHECK blocks writing a row into another tenant.

    Without WITH CHECK, a tenant could insert rows attributed to another lab —
    poisoning their data even while unable to read it.
    """
    set_tenant(BROAD)
    with pytest.raises(Exception) as exc:
        app_connection.execute(
            text(
                "INSERT INTO datasets (id, tenant_id, name, description) "
                "VALUES ('ds-injected', :t, 'injected', '')"
            ).bindparams(t=SANGER)
        )
    assert "policy" in str(exc.value).lower() or "row-level security" in str(exc.value).lower()


def test_cross_tenant_update_affects_no_rows(app_connection, set_tenant) -> None:
    """A tenant cannot modify another tenant's rows, even blindly."""
    set_tenant(BROAD)
    result = app_connection.execute(
        text(
            "UPDATE genomic_records SET specimen_label = 'tampered' "
            "WHERE tenant_id = :t"
        ).bindparams(t=SANGER)
    )
    assert result.rowcount == 0


def test_cross_tenant_delete_affects_no_rows(app_connection, set_tenant) -> None:
    set_tenant(BROAD)
    result = app_connection.execute(
        text("DELETE FROM genomic_records WHERE tenant_id = :t").bindparams(t=SANGER)
    )
    assert result.rowcount == 0


def test_every_tenant_has_data_so_isolation_tests_are_not_vacuous(
    app_connection, set_tenant
) -> None:
    """Guard against false confidence.

    If the seed failed and every tenant held zero rows, every isolation test
    above would pass trivially. This asserts each tenant actually has data to
    leak.
    """
    for tenant in ALL_TENANTS:
        set_tenant(tenant)
        count = app_connection.execute(
            text("SELECT count(*) FROM genomic_records")
        ).scalar_one()
        assert count > 0, f"{tenant} has no records; isolation tests would be vacuous"


def test_audit_log_is_append_only_for_the_app_role(app_connection) -> None:
    """UPDATE and DELETE are revoked at the GRANT level.

    A compromised application must not be able to rewrite its own audit trail,
    so this is enforced by PostgreSQL rather than by application convention.
    """
    granted = app_connection.execute(
        text(
            "SELECT privilege_type FROM information_schema.role_table_grants "
            "WHERE table_name = 'audit_entries' AND grantee = current_user"
        )
    ).scalars().all()
    assert "INSERT" in granted
    assert "SELECT" in granted
    assert "UPDATE" not in granted, "app role can rewrite audit history"
    assert "DELETE" not in granted, "app role can erase audit history"


def test_audit_update_actually_fails_at_runtime(app_connection, set_tenant) -> None:
    """The GRANT check above is necessary but not sufficient; prove it bites."""
    set_tenant(BROAD)
    app_connection.execute(
        text(
            "INSERT INTO audit_entries "
            "(id, tenant_id, actor_id, actor_role, action, resource_type, "
            " resource_id, allowed, reason) "
            "VALUES ('audit-immutability-probe', :t, 'u-1', 'researcher', 'read', "
            "        'dataset', 'ds-1', true, 'probe')"
        ).bindparams(t=BROAD)
    )
    with pytest.raises(Exception) as exc:
        app_connection.execute(
            text("UPDATE audit_entries SET reason = 'rewritten' WHERE id = :i").bindparams(
                i="audit-immutability-probe"
            )
        )
    assert "permission denied" in str(exc.value).lower()


def test_tenant_context_does_not_leak_between_transactions(
    app_connection, set_tenant
) -> None:
    """SET LOCAL is reverted at transaction end.

    With a plain SET, tenant context would persist on the pooled connection and
    the next request could inherit the previous request's tenant — a cross-
    tenant leak caused purely by connection reuse.
    """
    set_tenant(SANGER)
    assert app_connection.execute(
        text("SELECT count(*) FROM genomic_records")
    ).scalar_one() > 0

    app_connection.rollback()

    leaked = app_connection.execute(
        text("SELECT current_setting('biovault.tenant_id', true)")
    ).scalar_one()
    assert leaked in (None, ""), f"tenant context survived the transaction: {leaked!r}"
