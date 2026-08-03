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
)

# Audit entries are append-only: the app role may INSERT and SELECT but never
# UPDATE or DELETE. Enforced by GRANT, so a compromised application cannot
# rewrite its own trail.
APPEND_ONLY_TABLES: Final[tuple[str, ...]] = ("audit_entries",)


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
