"""Consortium consent and inbound epsilon accounting.

Two gaps in the federation layer are closed here: who may be queried at all,
and how much may be taken from any one of them.

## Why participation must be explicit

Membership in `tenants` is an isolation-boundary fact — it says a lab exists.
Treating it as consent to be a data source conflates "this lab is a customer"
with "this lab agreed to have its patients counted by strangers", which are
different decisions made by different people. `participating_sites()` returns
only labs that recorded the second one, so a lab that has not decided is
excluded rather than enrolled by default.

## Why inbound accounting is needed SEPARATELY from the outbound budget

The outbound budget in `biovault.federation.budget` is charged to the
*querier*. Each lab holds its own independent budget of DEFAULT_TOTAL_EPSILON,
and spends it on queries that fan out across every participating site.

Follow that through from the perspective of one lab being queried. With N
participating labs, each holding an independent budget B, every one of the
other N-1 labs can spend its full budget on queries that scan this lab's
records. The epsilon extracted from any single lab therefore scales as
(N-1) * B, while every outbound ledger involved remains perfectly in balance
and every individual querier is correctly refused once its own budget is gone.

Nothing in the outbound ledger observes this. It cannot: it is keyed by the
paying tenant, and each payer is individually compliant. The composition that
matters to a patient is not "how much did this lab spend" but "how much has
been released about me", and a patient at site S is exposed by every query
against S regardless of who paid. Sequential composition applies across
queriers exactly as it applies within one — the releases are over the same
underlying rows — so the leakage against S is the SUM over all queriers, which
is precisely the quantity no existing table records.

Adding labs to the consortium therefore silently degrades the guarantee for
every lab already in it. That is the wrong incentive for a consent-based
system: growth should not quietly cost existing participants privacy they
never agreed to spend.

This ledger is keyed by the lab being queried, so the sum it reports is the
one that bounds disclosure about that lab's patients. A lab sets its own
ceiling and is refused as a source once reached — independent of how many
other labs are asking, and independent of whether those labs are behaving.

## Relationship to the outbound budget

Both are charged, and a federated query must satisfy both. They are not
redundant: the outbound charge bounds what a querier can learn in total, the
inbound charge bounds what any one lab can be made to reveal. A query can be
legitimately refused by either, for different reasons, and the refusals mean
different things — outbound exhaustion is the querier's problem, inbound
exhaustion is the source lab's protection working as intended.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Final

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from biovault.federation.privacy import PrivacyError
from biovault.models.consortium import ConsortiumParticipation, InboundEpsilonEntry

# Default ceiling on epsilon extracted FROM one lab within the window.
#
# Deliberately NOT the same value as the outbound DEFAULT_TOTAL_EPSILON, and
# not derived from it. The two bound different things: outbound bounds one
# querier's total knowledge gain, inbound bounds total disclosure about one
# lab's patients from all queriers combined.
#
# 2.0 is set above a single lab's outbound budget of 1.0 on purpose. A ceiling
# at or below 1.0 would let one determined querier consume the entire
# consortium's access to a site by spending its own budget in one direction,
# turning inbound protection into a denial-of-service lever against the other
# participants. 2.0 admits roughly two labs' full budgets before the source is
# closed, which keeps the consortium usable while still bounding total
# extraction independently of N.
#
# This is a floor for safety, not a recommendation. A lab holding genuinely
# identifiable data should set `inbound_epsilon_limit` on its participation row
# well below this, and the per-lab override exists precisely so that decision
# belongs to the lab exposing the data rather than to this module.
DEFAULT_INBOUND_EPSILON_LIMIT: Final[float] = 2.0

# Rolling window, matching the outbound budget so the two accounts age out
# together. A shorter inbound window would let extraction resume against a lab
# while the queriers who performed it were still holding charges for it.
INBOUND_WINDOW_DAYS: Final[int] = 30


class SiteNotParticipating(PrivacyError):
    """Raised when a site is queried that has not opted in.

    A PrivacyError subclass so callers handle it alongside other privacy
    refusals, while remaining distinguishable from budget exhaustion: this one
    never resolves by waiting.
    """


class InboundBudgetExhausted(PrivacyError):
    """Raised when too much epsilon has already been extracted from a site.

    Distinct from `budget.BudgetExhausted`, which concerns the querier's own
    allowance. Conflating them would report a source lab's protective ceiling
    as the querier's quota problem and invite the wrong remediation — topping
    up the querier's budget, which does nothing and should do nothing.
    """


def _window_start(now: datetime) -> datetime:
    return now - timedelta(days=INBOUND_WINDOW_DAYS)


def participating_sites(session: Session) -> list[str]:
    """Tenant ids that have opted in to being federated data sources.

    Returns only labs with an active participation record. A lab absent from
    this table is excluded, so the failure mode of a missing or unwritten row
    is non-participation rather than silent enrollment.

    The caller is expected to use this in place of enumerating `tenants`
    directly. Note that this reads across tenants deliberately: participation
    is not a secret between participants — every member of a consortium knows
    who else is in it, and a federated result already discloses which sites
    contributed. What a lab holds stays protected by RLS on the data tables.
    """
    return list(
        session.execute(
            select(ConsortiumParticipation.tenant_id)
            .where(ConsortiumParticipation.participating.is_(True))
            .order_by(ConsortiumParticipation.tenant_id)
        )
        .scalars()
        .all()
    )


def is_participating(session: Session, *, tenant_id: str) -> bool:
    """Whether one lab has opted in. False when no record exists."""
    found = session.execute(
        select(ConsortiumParticipation.participating).where(
            ConsortiumParticipation.tenant_id == tenant_id
        )
    ).scalar_one_or_none()
    return bool(found)


def inbound_limit_for(
    session: Session,
    *,
    tenant_id: str,
    default_limit: float = DEFAULT_INBOUND_EPSILON_LIMIT,
) -> float:
    """The extraction ceiling a lab has set for itself, or the default.

    A lab with no explicit limit inherits `default_limit` rather than an
    unbounded one: omitting a value must not be a way to opt out of the
    ceiling while staying in the consortium.
    """
    configured = session.execute(
        select(ConsortiumParticipation.inbound_epsilon_limit).where(
            ConsortiumParticipation.tenant_id == tenant_id
        )
    ).scalar_one_or_none()
    return default_limit if configured is None else float(configured)


def extracted_epsilon(
    session: Session, *, tenant_id: str, now: datetime | None = None
) -> float:
    """Total epsilon extracted FROM a tenant within the current window.

    Summed across all querying tenants. That sum, not any single querier's
    contribution, is the quantity that bounds disclosure about this lab's
    patients.
    """
    current = now or datetime.now(UTC)
    total = session.execute(
        select(
            func.coalesce(func.sum(InboundEpsilonEntry.epsilon_extracted), 0.0)
        ).where(
            InboundEpsilonEntry.tenant_id == tenant_id,
            InboundEpsilonEntry.occurred_at >= _window_start(current),
        )
    ).scalar_one()
    return float(total)


def remaining_inbound_epsilon(
    session: Session,
    *,
    tenant_id: str,
    limit: float | None = None,
    now: datetime | None = None,
) -> float:
    """Epsilon that may still be extracted from a tenant. Never negative."""
    ceiling = (
        inbound_limit_for(session, tenant_id=tenant_id) if limit is None else limit
    )
    return max(0.0, ceiling - extracted_epsilon(session, tenant_id=tenant_id, now=now))


def record_extraction(
    session: Session,
    *,
    tenant_id: str,
    querying_tenant_id: str,
    actor_id: str,
    epsilon: float,
    query_fingerprint: str,
    limit: float | None = None,
    now: datetime | None = None,
) -> float:
    """Charge epsilon against a site's inbound ceiling, or refuse.

    Must be called BEFORE the site's records are counted, for the same reason
    the outbound budget is debited before the answer is computed: a crash
    between the read and the record would yield a disclosure nobody accounted
    for, and deliberately triggering that is an unlimited-extraction attack
    against the source lab.

    The session must already be bound to `tenant_id` — the lab being queried —
    because the ledger is tenant-scoped and the RLS WITH CHECK policy rejects
    an insert under any other tenant. This is also what makes the accounting
    correct: the row lands under the lab whose patients were exposed, not under
    the lab that paid.

    Args:
        tenant_id: The lab being queried. Its patients bear the disclosure.
        querying_tenant_id: The lab that asked. Recorded, not charged here.

    Returns:
        Remaining inbound allowance after the charge.

    Raises:
        SiteNotParticipating: If the site has not opted in, or has withdrawn.
        InboundBudgetExhausted: If the charge would exceed the site's ceiling.
    """
    current = now or datetime.now(UTC)

    if not is_participating(session, tenant_id=tenant_id):
        raise SiteNotParticipating(
            f"tenant {tenant_id!r} is not a participating federation site"
        )

    # Serialize concurrent extractions against this site. Without the lock, N
    # labs querying in parallel can each observe headroom and each consume it,
    # overshooting the ceiling by up to N-1 charges. That failure mode is
    # strictly more likely here than for the outbound budget: outbound
    # contention requires one tenant to issue concurrent queries, whereas
    # inbound contention is the normal state of a busy consortium, where
    # independent labs query the same popular site simultaneously.
    #
    # An advisory lock rather than SELECT ... FOR UPDATE, matching the outbound
    # ledger and for the same reason: row locks need UPDATE privilege, and this
    # table is deliberately append-only with the app role holding only INSERT
    # and SELECT. The lock key is namespaced separately from the outbound one
    # so a lab acting as both querier and source does not self-deadlock or
    # serialize against itself unnecessarily.
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:key))").bindparams(
            key=f"biovault:inbound_epsilon:{tenant_id}"
        )
    )

    ceiling = (
        inbound_limit_for(session, tenant_id=tenant_id) if limit is None else limit
    )
    already = extracted_epsilon(session, tenant_id=tenant_id, now=current)
    if already + epsilon > ceiling:
        raise InboundBudgetExhausted(
            f"inbound extraction budget exhausted for site {tenant_id!r}: "
            f"{already:.3f} of {ceiling:.3f} epsilon extracted, "
            f"request needs {epsilon:.3f}"
        )

    session.add(
        InboundEpsilonEntry(
            tenant_id=tenant_id,
            querying_tenant_id=querying_tenant_id,
            actor_id=actor_id,
            epsilon_extracted=epsilon,
            query_fingerprint=query_fingerprint,
            occurred_at=current,
        )
    )
    session.flush()

    return ceiling - (already + epsilon)


def assert_extractable(
    session: Session,
    *,
    tenant_id: str,
    epsilon: float,
    limit: float | None = None,
    now: datetime | None = None,
) -> None:
    """Raise if a site cannot absorb `epsilon` more extraction.

    A read-only precheck. Useful for refusing a whole federated query up front
    rather than after some sites have already been charged, which would leave
    the ledger recording disclosure for an answer the caller never received.

    Checking here does NOT make the charge safe to skip: between this call and
    `record_extraction` another querier may consume the headroom. The advisory
    lock inside `record_extraction` is the actual enforcement point; this is an
    optimization that improves the failure mode, not a substitute for it.

    Raises:
        SiteNotParticipating: If the site has not opted in, or has withdrawn.
        InboundBudgetExhausted: If the site's ceiling would be exceeded.
    """
    if not is_participating(session, tenant_id=tenant_id):
        raise SiteNotParticipating(
            f"tenant {tenant_id!r} is not a participating federation site"
        )

    remaining = remaining_inbound_epsilon(
        session, tenant_id=tenant_id, limit=limit, now=now
    )
    if epsilon > remaining:
        raise InboundBudgetExhausted(
            f"inbound extraction budget exhausted for site {tenant_id!r}: "
            f"{remaining:.3f} epsilon remaining, request needs {epsilon:.3f}"
        )


def participation_status(
    session: Session, *, tenant_id: str, now: datetime | None = None
) -> dict[str, float | bool | str]:
    """Report one site's participation state and remaining inbound allowance.

    The session must be bound to `tenant_id` for the ledger sum to be visible;
    an untenanted read sees zero rows under RLS and would report a full
    allowance no matter how much had been extracted.
    """
    ceiling = inbound_limit_for(session, tenant_id=tenant_id)
    extracted = extracted_epsilon(session, tenant_id=tenant_id, now=now)
    return {
        "tenant_id": tenant_id,
        "participating": is_participating(session, tenant_id=tenant_id),
        "inbound_limit": ceiling,
        "inbound_extracted": extracted,
        "inbound_remaining": max(0.0, ceiling - extracted),
    }
