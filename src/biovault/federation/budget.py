"""Privacy budget accounting.

Differential privacy composes: asking the same question twice at ε=0.1 each
leaks as much as asking once at ε=0.2. Noise is zero-mean, so an attacker who
repeats a query enough times can average the noise away and recover the exact
answer.

That makes the budget — not the noise — the actual privacy control. A DP
implementation without enforced accounting provides no guarantee at all, only
the appearance of one. This is the most common way DP is deployed incorrectly:
the noise is mathematically correct and the protection is still zero.

## Design

Each tenant holds a total epsilon budget over a rolling window. Every query
debits its epsilon *before* the answer is computed, and the debit is atomic
under concurrency. When the budget is exhausted, queries are refused —
including, deliberately, queries the analyst considers important. A budget that
can be topped up on request is not a budget.

## Why the debit happens before the answer

If the answer were computed first and the budget debited after, a crash or a
disconnect between the two would yield a disclosed answer that was never paid
for. Repeating that deliberately is an unlimited-query attack. Debiting first
means the failure mode is a paid-for answer the analyst never received — a loss
of utility, not of privacy.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Final

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from biovault.federation.privacy import PrivacyError
from biovault.models.tables import PrivacyBudgetEntry

# Total epsilon a tenant may spend within one window.
#
# Chosen by measuring the attack rather than by convention, and reported as an
# ATTACKER SUCCESS RATE rather than a median error -- a median says what
# happens on a typical attempt, but an attacker only needs to succeed once.
#
# A federated query costs e * len(sites), so with three labs a budget of 1.0 at
# e=0.1 buys 3 queries, not 10. Measured over 400 full attacks each, recovering
# a true count of 500 under that accounting:
#
#     e_total   e/query   queries   median err   pins the individual (+/-1)
#      10.0       0.1        33        2.21              25.0%
#       1.0       0.1         3        7.00               8.0%
#
# e_total=10.0 appears in plenty of DP tutorials. It lets an attacker state a
# specific person's genotype in a quarter of attempts, which is not a privacy
# guarantee in any useful sense. 1.0 is therefore the default: restrictive by
# design, because a genuinely private aggregate API answers few questions well
# rather than many questions uselessly.
#
# What 1.0 does NOT do, stated plainly: it does not defeat the differencing
# attack. It reduces the attacker's per-attempt success rate from ~25% to ~8%.
# Differential privacy bounds *expected* leakage; it does not eliminate it, and
# an individual attempt can still get lucky.
#
# Two corrections are recorded here rather than quietly folded in. An earlier
# version called 1.0 "differencing defeated" -- wrong, a nonzero success rate
# is not defeat. And these figures previously read 40.3%/14.3%, measured while
# the budget charged e once per federated query instead of once per site. That
# undercounted privacy loss threefold. Fixing it also tightened the real
# guarantee, which is why the corrected numbers are lower rather than higher.
#
# Operators holding genuinely identifiable data should lower this further and
# tune against their own threat model rather than inheriting this value.
DEFAULT_TOTAL_EPSILON: Final[float] = 1.0

# Rolling window over which the budget applies. Budget is not "reset" by an
# administrator; entries simply age out, so there is no privileged operation
# an attacker could induce to obtain more.
BUDGET_WINDOW_DAYS: Final[int] = 30


class BudgetExhausted(PrivacyError):
    """Raised when a tenant has no remaining privacy budget.

    A subclass of PrivacyError so callers can treat all privacy refusals
    uniformly, while monitoring can distinguish exhaustion from a malformed
    request.
    """


def _window_start(now: datetime) -> datetime:
    return now - timedelta(days=BUDGET_WINDOW_DAYS)


def spent_epsilon(
    session: Session, *, tenant_id: str, now: datetime | None = None
) -> float:
    """Total epsilon spent by a tenant within the current window."""
    current = now or datetime.now(UTC)
    total = session.execute(
        select(func.coalesce(func.sum(PrivacyBudgetEntry.epsilon_spent), 0.0)).where(
            PrivacyBudgetEntry.tenant_id == tenant_id,
            PrivacyBudgetEntry.occurred_at >= _window_start(current),
        )
    ).scalar_one()
    return float(total)


def remaining_epsilon(
    session: Session,
    *,
    tenant_id: str,
    total_budget: float = DEFAULT_TOTAL_EPSILON,
    now: datetime | None = None,
) -> float:
    """Epsilon a tenant may still spend. Never negative."""
    return max(0.0, total_budget - spent_epsilon(session, tenant_id=tenant_id, now=now))


def charge(
    session: Session,
    *,
    tenant_id: str,
    actor_id: str,
    epsilon: float,
    query_fingerprint: str,
    total_budget: float = DEFAULT_TOTAL_EPSILON,
    now: datetime | None = None,
) -> float:
    """Debit epsilon from a tenant's budget, or refuse.

    The row is inserted and flushed before this returns, so the charge is
    visible to any concurrent transaction that subsequently reads the ledger.
    The caller must compute the answer only after this succeeds.

    Args:
        query_fingerprint: A stable hash of the query. Recorded so an auditor
            can see *what* budget was spent on, and so repeated identical
            queries are visible as an averaging attempt.

    Returns:
        Remaining budget after the charge.

    Raises:
        BudgetExhausted: If the charge would exceed the tenant's budget.
    """
    current = now or datetime.now(UTC)

    # Serialize concurrent charges for this tenant. Without a lock, N parallel
    # requests can each observe sufficient budget and each spend it, overspending
    # by up to N-1 charges -- an easily triggered way to exceed the privacy
    # guarantee.
    #
    # An advisory lock rather than SELECT ... FOR UPDATE, because row locks
    # require UPDATE privilege on the table and the ledger is deliberately
    # append-only: the app role holds only INSERT and SELECT. Using a row lock
    # would have meant granting UPDATE, trading the immutability guarantee for
    # the concurrency one. An advisory lock needs no table privileges, is keyed
    # on the tenant, and PostgreSQL releases it automatically at COMMIT or
    # ROLLBACK.
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:key))").bindparams(
            key=f"biovault:privacy_budget:{tenant_id}"
        )
    )

    already_spent = spent_epsilon(session, tenant_id=tenant_id, now=current)
    if already_spent + epsilon > total_budget:
        raise BudgetExhausted(
            f"privacy budget exhausted for tenant {tenant_id!r}: "
            f"{already_spent:.3f} of {total_budget:.3f} epsilon spent, "
            f"request needs {epsilon:.3f}"
        )

    session.add(
        PrivacyBudgetEntry(
            tenant_id=tenant_id,
            actor_id=actor_id,
            epsilon_spent=epsilon,
            query_fingerprint=query_fingerprint,
            occurred_at=current,
        )
    )
    session.flush()

    return total_budget - (already_spent + epsilon)
