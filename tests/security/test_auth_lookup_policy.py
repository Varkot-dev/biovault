"""The pre-authentication identity-lookup exception must not widen data access.

Authentication has a bootstrap problem: a user's tenant is a property of the
user, so it cannot be known before the user is found — but the tenant policy
needs it to reveal any row. The narrow fix is a policy permitting SELECT on
`users` only while tenant context is unset.

Any exception to an isolation control deserves a test proving its blast radius,
because the tempting alternative (connecting as the schema owner during login)
would disable RLS across the whole authentication path. These tests are that
proof.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text

pytestmark = [pytest.mark.security, pytest.mark.rls, pytest.mark.integration]

DATA_TABLES = ("genomic_records", "datasets", "dataset_keys", "dataset_grants", "audit_entries")


def test_identity_lookup_works_without_tenant_context(app_connection, clear_tenant) -> None:
    """Without this, logging in is impossible."""
    clear_tenant()
    count = app_connection.execute(text("SELECT count(*) FROM users")).scalar_one()
    assert count > 0, "identity lookup is blocked; authentication cannot bootstrap"


@pytest.mark.parametrize("table", DATA_TABLES)
def test_auth_lookup_policy_does_not_widen_data_access(
    app_connection, clear_tenant, table: str
) -> None:
    """The exception covers `users` only.

    Every table holding tenant data must still return zero rows with no tenant
    context. This is the test that bounds the exception's blast radius.
    """
    clear_tenant()
    assert table in DATA_TABLES  # guards the interpolation below
    count = app_connection.execute(text(f"SELECT count(*) FROM {table}")).scalar_one()  # noqa: S608
    assert count == 0, f"{table} leaked rows through the auth-lookup exception"


def test_binding_a_tenant_re_narrows_the_users_table(app_connection, set_tenant) -> None:
    """The exception applies only to the pre-authentication window.

    Once a request binds a tenant, the tenant policy takes over and a user in
    one lab cannot enumerate another lab's staff.
    """
    set_tenant("lab-broad")
    tenants = app_connection.execute(
        text("SELECT DISTINCT tenant_id FROM users")
    ).scalars().all()
    assert tenants == ["lab-broad"]


def test_a_bound_tenant_cannot_see_another_labs_users(app_connection, set_tenant) -> None:
    set_tenant("lab-broad")
    count = app_connection.execute(
        text("SELECT count(*) FROM users WHERE tenant_id = 'lab-sanger'")
    ).scalar_one()
    assert count == 0


def test_auth_lookup_policy_is_select_only(app_connection, clear_tenant) -> None:
    """Reading identities to log in is necessary; writing them is not.

    A permissive INSERT here would let an unauthenticated caller create a user
    in any tenant — a complete authorization bypass.
    """
    clear_tenant()
    with pytest.raises(Exception) as exc:
        app_connection.execute(
            text(
                "INSERT INTO users (id, tenant_id, email, role, phi_cleared) "
                "VALUES ('u-injected', 'lab-sanger', 'attacker@evil.example', "
                "        'lab_admin', true)"
            )
        )
    message = str(exc.value).lower()
    assert "policy" in message or "row-level security" in message


def test_auth_lookup_policy_cannot_be_used_to_update_a_role(
    app_connection, clear_tenant
) -> None:
    """Privilege escalation via the auth window: promote yourself pre-login."""
    clear_tenant()
    result = app_connection.execute(
        text("UPDATE users SET role = 'lab_admin' WHERE role = 'read_only'")
    )
    assert result.rowcount == 0, "roles were modifiable without tenant context"
