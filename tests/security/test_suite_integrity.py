"""Guards against a security suite that passes without testing anything.

The integration tests skip when PostgreSQL is unreachable so the unit suite
stays runnable locally without Docker. That convenience creates a failure mode
worth defending against: CI could report a green security suite while every
database-backed test silently skipped.

Setting `BIOVAULT_REQUIRE_INTEGRATION=1` — which CI does — turns those skips
into failures.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import text

pytestmark = pytest.mark.security

REQUIRE_INTEGRATION = os.environ.get("BIOVAULT_REQUIRE_INTEGRATION") == "1"


@pytest.mark.skipif(
    not REQUIRE_INTEGRATION,
    reason="only enforced when BIOVAULT_REQUIRE_INTEGRATION=1 (CI)",
)
def test_database_is_reachable_when_integration_is_required() -> None:
    """In CI, an unreachable database must fail rather than skip.

    Without this, a misconfigured CI job would report a passing security suite
    having verified nothing about tenant isolation.
    """
    from tests.conftest import _app_url, _database_available

    assert _database_available(_app_url()), (
        "BIOVAULT_REQUIRE_INTEGRATION=1 but PostgreSQL is unreachable. "
        "The RLS isolation suite would have skipped, reporting false confidence."
    )


@pytest.mark.skipif(
    not REQUIRE_INTEGRATION,
    reason="only enforced when BIOVAULT_REQUIRE_INTEGRATION=1 (CI)",
)
def test_seed_data_exists_in_all_three_tenants() -> None:
    """The "3 research labs" claim needs three populated labs to be meaningful.

    Isolation tests comparing empty sets pass trivially.
    """
    from sqlalchemy import create_engine

    from tests.conftest import _app_url

    engine = create_engine(_app_url(), future=True)
    counts: dict[str, int] = {}
    with engine.connect() as conn:
        for tenant in ("lab-broad", "lab-sanger", "lab-riken"):
            conn.execute(
                text("SELECT set_config('biovault.tenant_id', :t, false)").bindparams(t=tenant)
            )
            counts[tenant] = conn.execute(
                text("SELECT count(*) FROM genomic_records")
            ).scalar_one()
    engine.dispose()

    empty = [t for t, c in counts.items() if c == 0]
    assert not empty, f"tenants with no seeded records: {empty} (counts={counts})"
