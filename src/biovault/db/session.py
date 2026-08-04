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


@contextmanager
def ledger_session(tenant_id: str) -> Iterator[Session]:
    """Yield a session for a privacy-ledger write that must survive failure.

    A privacy ledger and ordinary data work have **opposite** atomicity
    requirements, and this exists because putting them in one transaction gets
    the ledger's requirement backwards.

    A data transaction must roll back on error: committing half a write is
    worse than committing none. But a privacy debit must *persist* even when
    the query it paid for fails, because the disclosure already happened —
    the rows were read off disk regardless of whether the response was ever
    returned. Rolling the debit back means the read was free.

    That was not hypothetical. With the charge sharing the query's
    transaction, 30 deliberately-aborted queries performed 90 site reads
    across three labs and left both ledgers reading exactly zero. Repeating it
    averages the noise away, which is the precise attack `budget.py` says the
    ledger exists to prevent. No attacker is required either: a statement
    timeout, a connection reset, or a client disconnect unwinds identically.

    So this commits on its own connection, before the caller does any reading.
    A charge, once made, is durable no matter what happens next. The cost of
    getting it wrong in this direction is a caller charged for an answer they
    never received — a loss of utility, not of privacy.
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
