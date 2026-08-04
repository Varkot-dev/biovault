"""Federated cohort discovery across tenant boundaries.

The capability: a researcher at one lab asks "how many patients across all
three labs carry variant X?" and receives a differentially private answer
*without any lab's records leaving its tenant*.

## How isolation is preserved

Each site's count is computed inside a session bound to that site's tenant, so
RLS restricts the scan to that site's rows. Only the noised integer crosses the
boundary. No record, identifier, or exact count is ever shared.

This is the one operation in the system that legitimately spans tenants, and it
is precisely because it spans them that it must never return anything
record-level. `authz.policy.decide()` still refuses cross-tenant *record*
access; this path returns only privatized aggregates, which is a different
kind of answer subject to a different control — the privacy budget.

## The attack this must survive

The differencing attack: query a cohort, then query the same cohort minus one
individual, and subtract. Noise blunts a single attempt, but noise is zero-mean
— repeat and average and it cancels. The budget is therefore the real control,
and it is enforced here before any count is computed.
"""

from __future__ import annotations

import hashlib
import logging
import math
from typing import Final

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from biovault.db.rls import set_tenant_context
from biovault.db.session import untenanted_session
from biovault.federation.accuracy import (
    DEFAULT_ALPHA,
    MAX_ALPHA,
    MIN_ALPHA,
    ConfidenceInterval,
    interval_for,
)
from biovault.federation.budget import DEFAULT_TOTAL_EPSILON, charge, remaining_epsilon
from biovault.federation.privacy import (
    MAX_EPSILON,
    MIN_EPSILON,
    NoisyCount,
    combine_federated_counts,
    privatize_count,
)
from biovault.models.tables import GenomicRecord, Tenant

logger = logging.getLogger(__name__)

DEFAULT_EPSILON: Final[float] = 0.1


class CohortQuery(BaseModel):
    """A federated cohort-count query.

    Deliberately expressive enough to be scientifically useful and no more.
    There is no free-text predicate and no record selector: any filter precise
    enough to isolate one individual would defeat the aggregate guarantee no
    matter how much noise were added.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    variant_prefix: str = Field(min_length=2, max_length=40)
    epsilon: float = Field(default=DEFAULT_EPSILON, ge=MIN_EPSILON, le=MAX_EPSILON)
    # Significance level for the returned interval. Does not affect the noise
    # or the budget -- it only changes how the same uncertainty is reported,
    # so it is deliberately not part of the query fingerprint.
    alpha: float = Field(default=DEFAULT_ALPHA, ge=MIN_ALPHA, le=MAX_ALPHA)

    def fingerprint(self) -> str:
        """Stable hash identifying this query.

        Recorded on every budget debit so a run of identical fingerprints —
        the signature of an averaging attack — is visible to an auditor.

        `alpha` is excluded: it changes only the presentation of uncertainty,
        not what was asked. Including it would let an attacker vary alpha to
        make repeated identical queries look distinct in the audit trail.
        """
        return hashlib.sha256(
            f"variant_prefix={self.variant_prefix}".encode()
        ).hexdigest()


class SiteContribution(BaseModel):
    """One site's privatized contribution.

    `tenant_id` is included so an analyst knows which sites participated. The
    *count* is noised and, for small cohorts, suppressed — so participation is
    disclosed while the underlying data is not.
    """

    model_config = ConfigDict(frozen=True)

    tenant_id: str
    suppressed: bool


class FederatedCohortResult(BaseModel):
    """The answer to a federated cohort query.

    `total` is never returned without `interval`. A bare noised integer invites
    an analyst to treat it as exact — at the default epsilon the 95% interval
    is roughly ±30, which is the difference between a usable finding and a
    spurious one.
    """

    model_config = ConfigDict(frozen=True)

    total: int | None
    interval: ConfidenceInterval | None
    suppressed: bool
    sites_queried: int
    sites_contributing: int
    epsilon_spent: float
    epsilon_remaining: float
    noise_scale: float
    contributions: list[SiteContribution]


def _count_matching_records(session: Session, *, tenant_id: str, variant_prefix: str) -> int:
    """Count matching records within one tenant.

    The session is bound to `tenant_id` first, so RLS restricts the scan to
    that tenant's rows. Even if the WHERE clause were wrong, the policy would
    prevent this from reading another lab's data — the same defense-in-depth
    property the rest of the system relies on.

    Matching is on `specimen_label`, which is non-sensitive metadata. The
    genomic payload itself stays encrypted and is never decrypted here: a
    federated count must not require plaintext access to another lab's data.
    """
    set_tenant_context(session.connection(), tenant_id)

    escaped = (
        variant_prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    )
    return session.execute(
        select(func.count())
        .select_from(GenomicRecord)
        .where(GenomicRecord.specimen_label.like(f"%{escaped}%", escape="\\"))
    ).scalar_one()


def run_federated_cohort_query(
    *,
    query: CohortQuery,
    requesting_tenant: str,
    actor_id: str,
    total_budget: float = DEFAULT_TOTAL_EPSILON,
) -> FederatedCohortResult:
    """Answer a cohort query across all participating sites.

    Budget is charged to the *requesting* tenant before any count is computed.
    Charging afterwards would mean a crash between answer and debit yields a
    disclosed-but-unpaid answer, which is an unlimited-query attack when
    triggered deliberately.

    Raises:
        BudgetExhausted: If the requesting tenant has insufficient budget.
    """
    with untenanted_session() as session:
        # The budget ledger is tenant-scoped, so the requesting tenant must be
        # bound before the debit or the RLS WITH CHECK policy rejects the
        # insert. Binding it here also means the charge lands under the tenant
        # that pays for it, which is what makes per-tenant budgets meaningful.
        set_tenant_context(session.connection(), requesting_tenant)

        # Charge first. This raises BudgetExhausted before anything is read.
        remaining = charge(
            session,
            tenant_id=requesting_tenant,
            actor_id=actor_id,
            epsilon=query.epsilon,
            query_fingerprint=query.fingerprint(),
            total_budget=total_budget,
        )

        sites = session.execute(select(Tenant.id).order_by(Tenant.id)).scalars().all()

        per_site: list[NoisyCount] = []
        contributions: list[SiteContribution] = []

        for site in sites:
            true_count = _count_matching_records(
                session, tenant_id=site, variant_prefix=query.variant_prefix
            )
            # Each site privatizes its own count before it leaves the site.
            # The exact value is never held outside this loop iteration.
            noisy = privatize_count(true_count, epsilon=query.epsilon)
            per_site.append(noisy)
            contributions.append(
                SiteContribution(tenant_id=site, suppressed=noisy.suppressed)
            )

        combined = combine_federated_counts(per_site)

        logger.info(
            "federated cohort query: actor=%s tenant=%s fingerprint=%s "
            "sites=%d contributing=%d epsilon=%.3f remaining=%.3f",
            actor_id,
            requesting_tenant,
            query.fingerprint()[:12],
            len(sites),
            sum(1 for c in contributions if not c.suppressed),
            query.epsilon,
            remaining,
        )

        # Interval derived from the per-site scales that actually contributed.
        # Independent variances add, so a federated total is necessarily less
        # precise than any single site's answer.
        contributing_scales = [
            c.noise_scale for c in per_site if not c.suppressed
        ]
        interval = None
        if combined.value is not None and contributing_scales:
            interval = interval_for(
                combined.value,
                scale=math.sqrt(sum(s**2 for s in contributing_scales)),
                alpha=query.alpha,
            )

        return FederatedCohortResult(
            total=combined.value,
            interval=interval,
            suppressed=combined.suppressed,
            sites_queried=len(sites),
            sites_contributing=sum(1 for c in contributions if not c.suppressed),
            epsilon_spent=query.epsilon,
            epsilon_remaining=remaining,
            noise_scale=combined.noise_scale,
            contributions=contributions,
        )


def budget_status(
    *, tenant_id: str, total_budget: float = DEFAULT_TOTAL_EPSILON
) -> dict[str, float]:
    """Report a tenant's remaining privacy budget.

    The tenant must be bound before reading: the ledger is tenant-scoped, so
    an untenanted session sees zero rows and would report a full budget no
    matter how much had been spent — silently telling every analyst they had
    unlimited queries remaining.
    """
    with untenanted_session() as session:
        set_tenant_context(session.connection(), tenant_id)
        remaining = remaining_epsilon(
            session, tenant_id=tenant_id, total_budget=total_budget
        )
    return {
        "total": total_budget,
        "remaining": remaining,
        "spent": total_budget - remaining,
    }
