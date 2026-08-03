"""Database engines and tenant-scoped sessions.

Two engines exist for a security reason, not a convenience one:

- `owner_engine()` owns the schema. Used only by bootstrap and migrations.
- `app_engine()` is the least-privilege runtime role. Used by every request.

PostgreSQL bypasses row-level security for table owners, so serving requests
from the owner engine would silently disable tenant isolation at the database
layer. Keeping them as distinct functions makes that mistake visible.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from biovault.config import get_settings
from biovault.db.rls import clear_tenant_context, set_tenant_context


@lru_cache(maxsize=1)
def owner_engine() -> Engine:
    """Engine for the schema-owning role. Bootstrap and migrations only."""
    return create_engine(
        get_settings().database_url(as_owner=True),
        pool_pre_ping=True,
        future=True,
    )


@lru_cache(maxsize=1)
def app_engine() -> Engine:
    """Engine for the least-privilege runtime role. RLS applies here."""
    return create_engine(
        get_settings().database_url(as_owner=False),
        pool_pre_ping=True,
        future=True,
    )


@lru_cache(maxsize=1)
def _app_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=app_engine(), expire_on_commit=False, future=True)


@contextmanager
def tenant_session(tenant_id: str) -> Iterator[Session]:
    """Yield a session whose transaction is bound to one tenant.

    Tenant context is applied with `SET LOCAL`, so PostgreSQL clears it at
    COMMIT or ROLLBACK and it cannot leak to the next request that reuses this
    pooled connection.

    Every query inside this block is filtered by RLS to `tenant_id`, in
    addition to whatever the application-layer policy decides.
    """
    session = _app_sessionmaker()()
    try:
        set_tenant_context(session.connection(), tenant_id)
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@contextmanager
def untenanted_session() -> Iterator[Session]:
    """Yield an app-role session with no tenant bound.

    RLS matches zero rows on tenant-scoped tables here, which is intentional:
    this is for operations that legitimately precede tenant resolution, such
    as looking up an authorization code during a token exchange.
    """
    session = _app_sessionmaker()()
    try:
        clear_tenant_context(session.connection())
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
