"""Privacy budget enforcement.

`test_averaging_attack_is_stopped_by_the_budget` is the centrepiece. Its
companion in `test_differential_privacy.py` proves the averaging attack
*succeeds* without a budget; this proves the budget stops it.

Together they make the argument that noise is not the privacy control — the
budget is. A DP implementation with correct noise and unenforced accounting
provides no guarantee whatsoever, which is the most common way DP is deployed
incorrectly.
"""

from __future__ import annotations

import statistics
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from biovault.federation.budget import (
    BUDGET_WINDOW_DAYS,
    DEFAULT_TOTAL_EPSILON,
    BudgetExhausted,
    charge,
    remaining_epsilon,
    spent_epsilon,
)
from biovault.federation.privacy import privatize_count

pytestmark = [pytest.mark.security, pytest.mark.integration]

BROAD = "lab-broad"
SANGER = "lab-sanger"


@pytest.fixture
def tenant(owner_session) -> str:
    """A unique tenant per test.

    The budget ledger is append-only by design, so rows written by earlier
    tests persist. Scoping each test to its own tenant keeps assertions
    independent of execution order without weakening the immutability that
    makes cleanup impossible.
    """
    import uuid

    tenant_id = f"lab-budget-{uuid.uuid4().hex[:10]}"
    owner_session.execute(
        text("INSERT INTO tenants (id, name) VALUES (:i, :n)").bindparams(
            i=tenant_id, n="budget test tenant"
        )
    )
    owner_session.flush()
    return tenant_id


# --- The headline result ----------------------------------------------------


def test_averaging_attack_is_stopped_by_the_budget(owner_session, tenant: str) -> None:
    """The attack that makes DP-without-a-budget useless.

    Its companion, `test_averaging_defeats_noise_when_queries_are_unlimited`,
    shows that averaging 2000 noised answers recovers the true value to within
    ~0.14. Here the same attacker is cut off by the budget.

    The assertion is on the *residual error the attacker is left with*, not
    merely on the query count. A budget that cuts the attacker off after
    enough queries to average the noise away is not a control, and asserting
    only "was refused" would pass in exactly that broken case.

    The DEFAULT_TOTAL_EPSILON docstring records the measurements behind the
    chosen value.
    """
    epsilon = 0.1
    true_value = 500

    samples: list[int] = []
    refused_at: int | None = None

    for attempt in range(2000):
        try:
            charge(
                owner_session,
                tenant_id=tenant,
                actor_id="attacker",
                epsilon=epsilon,
                query_fingerprint="same-query-repeated",
                total_budget=DEFAULT_TOTAL_EPSILON,
            )
        except BudgetExhausted:
            refused_at = attempt
            break
        samples.append(privatize_count(true_value, epsilon=epsilon).value)

    expected_queries = int(DEFAULT_TOTAL_EPSILON / epsilon)
    assert refused_at == expected_queries, (
        f"expected exhaustion after {expected_queries} queries, got {refused_at}"
    )

    # The protective property. Standard error of the attacker's estimate is
    # (1/epsilon)/sqrt(n). A differencing attack must resolve a difference of
    # 1, so anything below ~3 leaves the attack viable.
    standard_error = (1.0 / epsilon) / len(samples) ** 0.5
    assert standard_error > 3.0, (
        f"budget permits {len(samples)} queries, leaving the attacker a "
        f"standard error of {standard_error:.2f} -- small enough to resolve "
        "a single individual by differencing"
    )


def test_budget_does_not_permit_enough_queries_to_average_out_noise(
    owner_session, tenant: str
) -> None:
    """Directly measures what an attacker recovers after exhausting the budget.

    Complements the analytic bound above with an empirical one: run the full
    attack repeatedly and assert the median recovery error stays large enough
    that a difference of 1 is unresolvable.
    """
    epsilon = 0.1
    true_value = 500
    permitted = int(DEFAULT_TOTAL_EPSILON / epsilon)

    errors = [
        abs(
            statistics.mean(
                privatize_count(true_value, epsilon=epsilon).value
                for _ in range(permitted)
            )
            - true_value
        )
        for _ in range(40)
    ]

    assert statistics.median(errors) > 1.5, (
        f"after exhausting the budget ({permitted} queries) the attacker's "
        f"median error is {statistics.median(errors):.2f}; a differencing "
        "attack resolving a difference of 1 would succeed"
    )


def test_budget_refuses_rather_than_degrading_quality(owner_session, tenant: str) -> None:
    """Exhaustion is a refusal, not a quietly worse answer.

    Silently increasing noise once the budget runs out would let an analyst
    keep querying while believing the results are as trustworthy as before.
    """
    charge(
        owner_session,
        tenant_id=tenant,
        actor_id="analyst",
        epsilon=10.0,
        query_fingerprint="q",
        total_budget=10.0,
    )
    with pytest.raises(BudgetExhausted):
        charge(
            owner_session,
            tenant_id=tenant,
            actor_id="analyst",
            epsilon=0.01,
            query_fingerprint="q",
            total_budget=10.0,
        )


# --- Accounting -------------------------------------------------------------


def test_spend_accumulates(owner_session, tenant: str) -> None:
    for _ in range(5):
        charge(
            owner_session,
            tenant_id=tenant,
            actor_id="analyst",
            epsilon=0.2,
            query_fingerprint="q",
        )
    assert spent_epsilon(owner_session, tenant_id=tenant) == pytest.approx(1.0)


def test_remaining_decreases_as_budget_is_spent(owner_session, tenant: str) -> None:
    before = remaining_epsilon(owner_session, tenant_id=tenant, total_budget=10.0)
    charge(
        owner_session,
        tenant_id=tenant,
        actor_id="analyst",
        epsilon=2.5,
        query_fingerprint="q",
        total_budget=10.0,
    )
    after = remaining_epsilon(owner_session, tenant_id=tenant, total_budget=10.0)
    assert before - after == pytest.approx(2.5)


def test_charge_returns_remaining_budget(owner_session, tenant: str) -> None:
    remaining = charge(
        owner_session,
        tenant_id=tenant,
        actor_id="analyst",
        epsilon=1.0,
        query_fingerprint="q",
        total_budget=10.0,
    )
    assert remaining == pytest.approx(9.0)


def test_a_charge_exceeding_the_budget_is_refused_atomically(
    owner_session, tenant: str
) -> None:
    """A refused charge must not be recorded.

    Otherwise a rejected query would still consume budget, and an attacker
    could drain a tenant's allowance with requests that never return data.
    """
    charge(
        owner_session,
        tenant_id=tenant,
        actor_id="analyst",
        epsilon=9.5,
        query_fingerprint="q",
        total_budget=10.0,
    )
    before = spent_epsilon(owner_session, tenant_id=tenant)

    with pytest.raises(BudgetExhausted):
        charge(
            owner_session,
            tenant_id=tenant,
            actor_id="analyst",
            epsilon=1.0,
            query_fingerprint="q",
            total_budget=10.0,
        )

    assert spent_epsilon(owner_session, tenant_id=tenant) == pytest.approx(before)


# --- Isolation between tenants ----------------------------------------------


def test_budgets_are_per_tenant(owner_session, tenant: str) -> None:
    """One lab exhausting its budget must not affect another's.

    A shared budget would let any tenant deny service to every other tenant.
    """
    charge(
        owner_session,
        tenant_id=tenant,
        actor_id="analyst",
        epsilon=10.0,
        query_fingerprint="q",
        total_budget=10.0,
    )
    assert spent_epsilon(owner_session, tenant_id=tenant) == pytest.approx(10.0)
    assert remaining_epsilon(owner_session, tenant_id=SANGER, total_budget=10.0) > 0


def test_one_tenant_cannot_exhaust_another(owner_session, tenant: str) -> None:
    charge(
        owner_session,
        tenant_id=tenant,
        actor_id="attacker",
        epsilon=10.0,
        query_fingerprint="q",
        total_budget=10.0,
    )
    # A different tenant's charge still succeeds.
    charge(
        owner_session,
        tenant_id=BROAD,
        actor_id="analyst",
        epsilon=0.1,
        query_fingerprint="q",
        total_budget=10.0,
    )


# --- Window behaviour -------------------------------------------------------


def test_spend_outside_the_window_does_not_count(owner_session, tenant: str) -> None:
    """Budget ages out; it is never reset by a privileged operation.

    An administrator "resetting" a budget would be an operation an attacker
    could try to induce. Ageing removes that target entirely.
    """
    stale = datetime.now(UTC) - timedelta(days=BUDGET_WINDOW_DAYS + 1)
    charge(
        owner_session,
        tenant_id=tenant,
        actor_id="analyst",
        epsilon=9.0,
        query_fingerprint="q",
        total_budget=10.0,
        now=stale,
    )
    assert spent_epsilon(owner_session, tenant_id=tenant) == pytest.approx(0.0)


def test_spend_inside_the_window_still_counts(owner_session, tenant: str) -> None:
    recent = datetime.now(UTC) - timedelta(days=BUDGET_WINDOW_DAYS - 1)
    charge(
        owner_session,
        tenant_id=tenant,
        actor_id="analyst",
        epsilon=3.0,
        query_fingerprint="q",
        total_budget=10.0,
        now=recent,
    )
    assert spent_epsilon(owner_session, tenant_id=tenant) == pytest.approx(3.0)


# --- Ledger integrity -------------------------------------------------------


def test_query_fingerprint_is_recorded(owner_session, tenant: str) -> None:
    """A run of identical fingerprints is the signature of an averaging attack.

    Recording them makes that pattern visible to an auditor rather than
    invisible.
    """
    charge(
        owner_session,
        tenant_id=tenant,
        actor_id="analyst",
        epsilon=0.1,
        query_fingerprint="fingerprint-abc",
    )
    stored = owner_session.execute(
        text(
            "SELECT query_fingerprint FROM privacy_budget_entries "
            "WHERE tenant_id = :t"
        ).bindparams(t=tenant)
    ).scalars().all()
    assert stored == ["fingerprint-abc"]


def test_budget_ledger_is_append_only_for_the_app_role(app_connection) -> None:
    """A tenant able to delete its own budget rows has unlimited queries.

    Enforced by GRANT, like the audit log, so a compromised application cannot
    grant itself more privacy budget.
    """
    granted = app_connection.execute(
        text(
            "SELECT privilege_type FROM information_schema.role_table_grants "
            "WHERE table_name = 'privacy_budget_entries' AND grantee = current_user"
        )
    ).scalars().all()
    assert "INSERT" in granted
    assert "SELECT" in granted
    assert "UPDATE" not in granted, "budget entries can be rewritten"
    assert "DELETE" not in granted, "budget entries can be erased for a fresh allowance"


def test_deleting_budget_entries_fails_at_runtime(app_connection, set_tenant) -> None:
    """Prove the GRANT actually bites, not just that it is absent."""
    set_tenant(BROAD)
    app_connection.execute(
        text(
            "INSERT INTO privacy_budget_entries "
            "(id, tenant_id, actor_id, epsilon_spent, query_fingerprint) "
            "VALUES ('budget-probe', :t, 'u-1', 0.1, 'probe')"
        ).bindparams(t=BROAD)
    )
    with pytest.raises(Exception) as exc:
        app_connection.execute(
            text("DELETE FROM privacy_budget_entries WHERE id = 'budget-probe'")
        )
    assert "permission denied" in str(exc.value).lower()


def test_budget_entries_are_tenant_isolated(app_connection, set_tenant) -> None:
    """One lab must not read another's query history.

    Which variants a lab is researching is itself commercially and
    scientifically sensitive.
    """
    set_tenant(BROAD)
    app_connection.execute(
        text(
            "INSERT INTO privacy_budget_entries "
            "(id, tenant_id, actor_id, epsilon_spent, query_fingerprint) "
            "VALUES ('budget-iso-probe', :t, 'u-1', 0.1, 'secret-research-direction')"
        ).bindparams(t=BROAD)
    )

    set_tenant(SANGER)
    visible = app_connection.execute(
        text("SELECT count(*) FROM privacy_budget_entries WHERE id = 'budget-iso-probe'")
    ).scalar_one()
    assert visible == 0
