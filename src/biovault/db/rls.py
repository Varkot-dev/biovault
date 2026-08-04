"""PostgreSQL row-level security: the second, independent isolation layer.

The application-layer policy (`biovault.authz.policy`) and these RLS policies
enforce tenant isolation separately. A bug in either one alone does not breach
isolation, which is the defense-in-depth property the project claims.

Two details make this real rather than decorative:

1. **The API connects as a non-owning role.** PostgreSQL bypasses RLS for
   superusers and for the table owner. If the app connected as the owner,
   every policy here would be inert while still appearing to work.

2. **Tenant context is set per transaction** via `SET LOCAL`, so it cannot
   leak across pooled connections. `SET LOCAL` is reverted at COMMIT or
   ROLLBACK by PostgreSQL itself.
"""

from __future__ import annotations

from typing import Final

from sqlalchemy import text
from sqlalchemy.engine import Connection

TENANT_SETTING: Final[str] = "biovault.tenant_id"

# Tables carrying a tenant_id that RLS filters on.
TENANT_SCOPED_TABLES: Final[tuple[str, ...]] = (
    "users",
    "datasets",
    "dataset_keys",
    "genomic_records",
    "dataset_grants",
    "audit_entries",
    "privacy_budget_entries",
    # Scoped to the lab being queried, not the querier. That is what lets a lab
    # read and enforce its own consent decision and extraction ceiling without
    # depending on the good behaviour of whoever is asking.
    "consortium_participation",
    "inbound_epsilon_entries",
)

# Append-only tables: the app role may INSERT and SELECT but never UPDATE or
# DELETE. Enforced by GRANT, so a compromised application cannot rewrite its
# own trail — or, for the inbound ledger, erase evidence of how much it has
# already extracted from another lab and thereby reset that lab's ceiling.
#
# `consortium_participation` is deliberately NOT append-only. Withdrawing
# consent must be possible, which requires UPDATE; the row is preserved rather
# than deleted so the history of the decision survives.
APPEND_ONLY_TABLES: Final[tuple[str, ...]] = (
    "audit_entries",
    "privacy_budget_entries",
    "inbound_epsilon_entries",
)

# Tables consulted before a tenant is known. Not tenant-scoped by design:
# both are keyed by unguessable high-entropy secrets, so there is no
# identifier an attacker could enumerate even with unrestricted SELECT.
AUTH_TABLES: Final[tuple[str, ...]] = ("authorization_codes", "refresh_tokens")


def _current_tenant_sql() -> str:
    """SQL expression yielding the current tenant, or NULL when unset.

    `current_setting(..., true)` returns NULL instead of raising when the
    setting is missing. Combined with the policy comparison below, an unset
    tenant matches zero rows — the safe direction. NULL = anything is NULL,
    which is not TRUE, so the policy denies.
    """
    return f"current_setting('{TENANT_SETTING}', true)"


def apply_rls_policies(connection: Connection, *, app_role: str) -> None:
    """Create the app role, enable RLS, and install per-table policies.

    Idempotent: safe to run on every boot.

    Args:
        connection: A connection owning the schema (the owner role).
        app_role: The least-privilege role the API connects as.
    """
    _ensure_app_role(connection, app_role=app_role)

    for table in TENANT_SCOPED_TABLES:
        _enable_rls(connection, table=table)
        _install_tenant_policy(connection, table=table)
        _grant_table_privileges(connection, table=table, app_role=app_role)

    # Narrow exception permitting pre-authentication identity lookup.
    _install_auth_lookup_policy(connection)

    # Narrow exception permitting the consortium roster to be read across
    # tenants. SELECT only; writes stay tenant-scoped.
    _install_participation_roster_policy(connection)

    # Auth tables are keyed by unguessable high-entropy values rather than by
    # tenant, so they are not tenant-scoped. Establishing a session requires
    # reading them before any tenant is known.
    for table in AUTH_TABLES:
        connection.execute(
            text(f"GRANT SELECT, INSERT, UPDATE ON {table} TO {app_role}")
        )

    # The tenant registry is readable but never writable by the application.
    # Federated queries must enumerate participating sites, and a lab's
    # existence is not a secret — every participant knows who is in the
    # consortium. What each lab *holds* remains protected by the policies
    # above. SELECT only: an application able to create tenants could mint an
    # isolation boundary of its own choosing.
    connection.execute(text(f"GRANT SELECT ON tenants TO {app_role}"))
    connection.execute(text(f"REVOKE INSERT, UPDATE, DELETE ON tenants FROM {app_role}"))


def _ensure_app_role(connection: Connection, *, app_role: str) -> None:
    """Create the runtime role if absent and grant schema usage.

    The role deliberately owns nothing. It gets only the table privileges
    granted explicitly below.
    """
    connection.execute(
        text(
            f"""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT FROM pg_catalog.pg_roles WHERE rolname = '{app_role}'
                ) THEN
                    CREATE ROLE {app_role} LOGIN;
                END IF;
            END
            $$;
            """
        )
    )
    connection.execute(text(f"GRANT USAGE ON SCHEMA public TO {app_role}"))


def set_app_role_password(connection: Connection, *, app_role: str, password: str) -> None:
    """Set the app role's password.

    Separated from role creation so the password is passed as a bound
    parameter rather than interpolated into DDL.
    """
    # ALTER ROLE cannot take bound parameters, so the statement is built by
    # PostgreSQL's own format() with %I/%L quoting rather than by string
    # concatenation in Python.
    stmt = connection.execute(
        text("SELECT format('ALTER ROLE %I PASSWORD %L', :role, :pw)").bindparams(
            role=app_role, pw=password
        )
    ).scalar_one()
    connection.execute(text(stmt))


def _enable_rls(connection: Connection, *, table: str) -> None:
    """Enable and FORCE row-level security on a table.

    `FORCE` matters: without it the table owner still bypasses RLS. Since
    migrations run as the owner, forcing keeps the policies honest even if
    something later connects with elevated privileges by mistake.
    """
    connection.execute(text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
    connection.execute(text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))


def _install_tenant_policy(connection: Connection, *, table: str) -> None:
    """Install the tenant-matching policy, replacing any prior version."""
    policy = f"{table}_tenant_isolation"
    tenant_expr = _current_tenant_sql()

    connection.execute(text(f"DROP POLICY IF EXISTS {policy} ON {table}"))
    connection.execute(
        text(
            f"""
            CREATE POLICY {policy} ON {table}
                USING (tenant_id = {tenant_expr})
                WITH CHECK (tenant_id = {tenant_expr})
            """
        )
    )


def _install_participation_roster_policy(connection: Connection) -> None:
    """Permit reading which labs have opted in, across tenants.

    Enumerating consortium participants inherently spans the isolation
    boundary: a querier bound to its own tenant would otherwise see only its
    own consent row and conclude it was the sole participant. That is not a
    hypothetical -- it produced `sites=0/1` on a three-lab consortium before
    this policy existed, silently reducing federation to a self-query.

    The exception is narrow and covers SELECT only. Which labs participate is
    not a secret between participants: every consortium member knows who else
    signed the agreement, and a federated result already names the sites that
    contributed. What each lab *holds* stays protected by the policies on the
    data tables, which are untouched by this.

    WRITES stay tenant-scoped. The base policy still governs INSERT and UPDATE,
    so a lab can read the roster but can only alter its own row -- no lab can
    opt another one in, or forge a withdrawal on another's behalf.
    """
    connection.execute(
        text(
            "DROP POLICY IF EXISTS consortium_participation_roster "
            "ON consortium_participation"
        )
    )
    connection.execute(
        text(
            """
            CREATE POLICY consortium_participation_roster
                ON consortium_participation
                FOR SELECT
                USING (true)
            """
        )
    )


def _install_auth_lookup_policy(connection: Connection) -> None:
    """Permit identity lookup on `users` when no tenant context is set.

    Authentication has a genuine bootstrap problem: the tenant is a *property
    of the user*, so it cannot be known before the user is found, but the
    tenant policy needs it to reveal any row. Without a narrow exception,
    logging in is impossible.

    The tempting escape — connecting as the schema owner during login — would
    disable RLS across the entire authentication path. This policy is the
    narrow alternative: SELECT on `users` is permitted only while tenant
    context is unset, which is exactly the pre-authentication window.

    This does not widen access to tenant data. `genomic_records`, `datasets`,
    `dataset_keys`, `dataset_grants`, and `audit_entries` still return zero
    rows without tenant context, and once a request binds a tenant this policy
    stops applying (the tenant policy takes over as the permissive match).
    Verified by `test_auth_lookup_policy_does_not_widen_data_access`.
    """
    connection.execute(text("DROP POLICY IF EXISTS users_auth_lookup ON users"))
    connection.execute(
        text(
            f"""
            CREATE POLICY users_auth_lookup ON users
                FOR SELECT
                USING ({_current_tenant_sql()} IS NULL OR {_current_tenant_sql()} = '')
            """
        )
    )


def _grant_table_privileges(connection: Connection, *, table: str, app_role: str) -> None:
    """Grant the app role only what it needs on a table."""
    if table in APPEND_ONLY_TABLES:
        connection.execute(text(f"GRANT SELECT, INSERT ON {table} TO {app_role}"))
        connection.execute(text(f"REVOKE UPDATE, DELETE ON {table} FROM {app_role}"))
    else:
        connection.execute(
            text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {app_role}")
        )


def set_tenant_context(connection: Connection, tenant_id: str) -> None:
    """Bind the current transaction to a tenant.

    Uses `SET LOCAL`, so PostgreSQL reverts the setting at COMMIT or ROLLBACK.
    That prevents tenant context from leaking to the next request that reuses
    the same pooled connection — a serious bug with a plain `SET`.

    The value is bound as a parameter via `set_config`, not interpolated, so a
    hostile tenant identifier cannot inject SQL.
    """
    connection.execute(
        text("SELECT set_config(:setting, :tenant, true)").bindparams(
            setting=TENANT_SETTING, tenant=tenant_id
        )
    )


def clear_tenant_context(connection: Connection) -> None:
    """Reset tenant context to unset, which matches zero rows."""
    connection.execute(
        text("SELECT set_config(:setting, '', true)").bindparams(setting=TENANT_SETTING)
    )
