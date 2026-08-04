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
from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from biovault.db.rls import set_tenant_context
from biovault.db.session import ledger_session, untenanted_session
from biovault.federation.accuracy import (
    DEFAULT_ALPHA,
    MAX_ALPHA,
    MIN_ALPHA,
    ConfidenceInterval,
    interval_for,
)
from biovault.federation.budget import DEFAULT_TOTAL_EPSILON, charge, remaining_epsilon
from biovault.federation.consent import (
    InboundBudgetExhausted,
    SiteNotParticipating,
    assert_extractable,
    participating_sites,
    record_extraction,
)
from biovault.federation.privacy import (
    MAX_EPSILON,
    MIN_EPSILON,
    NoisyCount,
    PrivacyError,
    combine_federated_counts,
    privatize_count,
)
from biovault.models.tables import GenomicRecord

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

    # The gene symbol whose carriers are being counted, e.g. "BRCA1". Matched
    # for exact equality against `GenomicRecord.gene_symbol`, not as a prefix
    # or substring: gene symbols are a controlled vocabulary, so an exact match
    # is what the question actually means. It is also the safer predicate --
    # substring matching lets a caller shrink a filter step by step until it
    # selects a single record, and progressively narrowing a cohort is the
    # setup for a differencing attack.
    gene: str = Field(min_length=2, max_length=40)
    epsilon: float = Field(default=DEFAULT_EPSILON, ge=MIN_EPSILON, le=MAX_EPSILON)
    # Significance level for the returned interval. Does not affect the noise
    # or the budget -- it only changes how the same uncertainty is reported,
    # so it is deliberately not part of the query fingerprint.
    alpha: float = Field(default=DEFAULT_ALPHA, ge=MIN_ALPHA, le=MAX_ALPHA)

    def fingerprint(self) -> str:
        """Stable hash identifying this query.

        Recorded on every budget debit so a run of identical fingerprints —
        the signature of an averaging attack — is visible to an auditor.

        **The hash is deliberately narrow: it covers `gene` and nothing
        else.** Only the predicate identifies *what was asked*.
        `epsilon` and `alpha` control how precisely the answer is reported, not
        which individuals it concerns, so varying them must not produce a new
        fingerprint.

        This matters for any field added later. A field included here "for
        completeness" would hand an attacker a way to fragment their own audit
        trail: ask the same question a hundred times with a hundred slightly
        different values, and a hundred distinct fingerprints make an averaging
        attack look like ordinary varied research. Before adding a field to
        this hash, ask whether two queries differing only in that field are
        asking about the same people. If they are, leave it out.
        """
        return hashlib.sha256(f"gene={self.gene}".encode()).hexdigest()


class SiteStatus(StrEnum):
    """Why a site did or did not contribute to a federated total.

    Three distinct outcomes that must not share one flag. `SUPPRESSED` is a
    differentially private release — the site was read and its noised count
    fell below the threshold. `UNAVAILABLE` is administrative: nothing was
    read, no noise was drawn, no epsilon is owed.

    Collapsing them (as an earlier version did) puts an unprotected
    administrative signal on a channel whose privacy analysis covers only the
    protected one — and does not even hide it, since the two separate on
    whether the inbound ledger moved.
    """

    CONTRIBUTED = "contributed"
    SUPPRESSED = "suppressed"
    UNAVAILABLE = "unavailable"


class SiteContribution(BaseModel):
    """One site's outcome in a federated query.

    `tenant_id` is included so an analyst knows which sites participated —
    participation is disclosed while the underlying data is not.
    """

    model_config = ConfigDict(frozen=True)

    tenant_id: str
    status: SiteStatus

    @property
    def suppressed(self) -> bool:
        """Backwards-compatible view: did this site withhold a count?

        True for both `SUPPRESSED` and `UNAVAILABLE`. Retained so existing
        callers keep working, but new code should read `status` — the two
        cases have different privacy meanings and this property erases the
        distinction.
        """
        return self.status is not SiteStatus.CONTRIBUTED


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


def _count_matching_records(session: Session, *, tenant_id: str, gene: str) -> int:
    """Count records carrying a call in `gene` within one tenant.

    The session is bound to `tenant_id` first, so RLS restricts the scan to
    that tenant's rows. Even if the WHERE clause were wrong, the policy would
    prevent this from reading another lab's data — the same defense-in-depth
    property the rest of the system relies on.

    Matching is on `GenomicRecord.gene_symbol`, a plaintext column holding only
    the non-identifying gene name; see that model for why that one component of
    a variant call is safe to store in the clear. The full call — position,
    genotype, depth — stays inside `payload_ciphertext` and is **never
    decrypted here**. That is the load-bearing property of this function: a
    federated count must not require plaintext access to another lab's data,
    so if this path ever needs a decrypt, the capability is broken rather than
    extended.

    Equality, not LIKE. The value is bound as a parameter either way, so this
    is not about injection — it is about *filter widening*. A LIKE pattern
    lets a caller pass `%` and match every row, or narrow a filter one
    character at a time until it isolates an individual. Exact match against a
    controlled vocabulary admits neither: the predicate either names a real
    gene or matches nothing.

    ## Counts subjects, not rows

    `COUNT(DISTINCT specimen_label)`, not `COUNT(*)`. The two differ, and the
    difference is a privacy bug rather than a rounding detail.

    The Laplace mechanism adds noise calibrated to the query's *sensitivity* —
    how much one individual joining or leaving can move the answer. Every
    epsilon figure in this system assumes that is 1. `COUNT(*)` breaks the
    assumption the moment one subject has two rows matching one gene, which is
    not hypothetical: compound heterozygosity (two pathogenic variants in the
    same gene) is the textbook clinical case for BRCA1 and CFTR, both in the
    seed vocabulary. Longitudinal resequencing and tumour/normal pairs do the
    same.

    Under `COUNT(*)`, a subject with k rows moves the count by k while the
    mechanism still adds Laplace(1/epsilon). Delivered privacy silently
    degrades to k*epsilon while every ledger records epsilon -- the same class
    of error as charging epsilon once for a release that costs epsilon per
    site, on the sensitivity axis instead of the composition axis.

    `COUNT(DISTINCT specimen_label)` makes sensitivity 1 true by construction:
    one subject changes the result by at most one, whatever their row count.
    `specimen_label` is a *within-tenant* identifier, which is why this fix
    needs no cross-tenant linkage and does not touch the isolation model.
    Bounding a subject's exposure *across* labs is a separate and much harder
    problem -- see the design note on the unit of privacy.
    """
    set_tenant_context(session.connection(), tenant_id)

    return session.execute(
        select(func.count(func.distinct(GenomicRecord.specimen_label)))
        .select_from(GenomicRecord)
        .where(GenomicRecord.gene_symbol == gene)
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

        # Sites must be enumerated BEFORE the charge, because the cost depends
        # on how many of them there are.
        #
        # Only labs that have opted in. Enumerating every row in `tenants`
        # would enrol a lab as a data source purely by existing, which is the
        # opposite of the consent-compatible framing this endpoint claims. A
        # lab with no participation record is treated as not participating, so
        # the default is exclusion rather than grandfathering.
        sites = participating_sites(session)
        if not sites:
            raise PrivacyError("no sites are participating in federated queries")

        # Filter to the sites that can actually absorb this query BEFORE
        # charging, using the read-only precheck in `consent`.
        #
        # Without it, the querier is charged for every participating site and
        # then some of them refuse mid-loop. Those refusals are correct -- one
        # exhausted lab must not be able to deny the whole consortium -- but
        # charging for a site that never ran is accounting for work that did
        # not happen. Worse, if enough sites refuse, `combine_federated_counts`
        # suppresses the total at `min_contributing_sites` and the epsilon
        # already taken from the sites that DID run bought nothing.
        #
        # The precheck is a filter rather than a gate: the query proceeds with
        # whatever subset can serve it, and the outbound charge is sized to
        # that subset, so a caller pays for the labs that actually answered.
        #
        # This does not make the per-site charge redundant. Between this check
        # and that charge another querier may consume the remaining ceiling, so
        # `record_extraction` still enforces it under a lock. The precheck
        # narrows the window; it does not close it, and the mid-loop handler
        # below remains the authority.
        servable: list[str] = []
        for site in sites:
            try:
                assert_extractable(session, tenant_id=site, epsilon=query.epsilon)
            except (InboundBudgetExhausted, SiteNotParticipating):
                continue
            servable.append(site)

        if not servable:
            raise PrivacyError(
                "no participating site can absorb this query's privacy cost"
            )

        # One query produces one Laplace release PER SITE, and the requester
        # observes all of them. Under sequential composition the privacy cost
        # is therefore epsilon * len(sites), not epsilon.
        #
        # Charging epsilon once would undercount by the site multiplier: with
        # three labs, a budget of 1.0 at epsilon=0.1 would permit 10 queries
        # and 30 releases while the ledger recorded 10. That is a real leak of
        # 3x the stated amount, and it was how this function originally
        # behaved.
        #
        # WHY SEQUENTIAL AND NOT PARALLEL COMPOSITION. If the labs held
        # disjoint patient populations, parallel composition would apply and
        # the true cost would be epsilon: a given person appears at exactly one
        # site, so the releases do not compound for them. BioVault does not
        # assume that. In a real genomics consortium patients DO appear at
        # multiple institutions -- which is precisely why cross-lab queries are
        # scientifically valuable -- and there is no way to detect overlap
        # without linking identities across tenants, which the whole system
        # exists to prevent. Sequential composition is the safe reading when
        # overlap cannot be ruled out.
        # Sized to the sites that will actually run, not to every participant.
        total_cost = query.epsilon * len(servable)

        # Charge first, ON ITS OWN COMMITTED TRANSACTION. Raises
        # BudgetExhausted before anything is read.
        #
        # The separate transaction is the load-bearing part. `charge()` used to
        # run inside this function's session, which flushes but does not commit
        # until the function returns -- so any later exception rolled the debit
        # back while the site reads had already happened. Measured: 30
        # deliberately-aborted queries performed 90 site reads across three
        # labs and left both ledgers at exactly zero, which is unlimited free
        # querying and defeats the budget outright.
        #
        # A privacy debit and a data read have opposite atomicity needs. The
        # read either happened or it did not, and if it happened the
        # disclosure is real whether or not the caller ever saw the response.
        # So the debit must outlive the transaction that triggered it.
        with ledger_session(requesting_tenant) as ledger:
            remaining = charge(
                ledger,
                tenant_id=requesting_tenant,
                actor_id=actor_id,
                epsilon=total_cost,
                query_fingerprint=query.fingerprint(),
                total_budget=total_budget,
            )

        per_site: list[NoisyCount] = []
        contributions: list[SiteContribution] = []

        # Sites filtered out by the precheck are reported but never charged
        # and never read: nothing was disclosed, so nothing is owed.
        for site in sites:
            if site not in servable:
                contributions.append(
                    SiteContribution(tenant_id=site, status=SiteStatus.UNAVAILABLE)
                )

        for site in servable:
            # Charge the source lab's extraction ceiling before reading it, on
            # its own committed transaction for the same reason as the outbound
            # charge above: the read is what discloses, so the debit must
            # survive a later failure of this query.
            #
            # The outbound budget alone does not bound this. It is charged to
            # the querier, so with N participating labs each holding an
            # independent budget, total leakage against any one lab scales with
            # N and nothing tracked it. A lab could be drained by the
            # consortium while its own budget sat untouched. This is the
            # counterpart that lets a lab bound what is taken *from* it,
            # regardless of how many others are asking.
            try:
                with ledger_session(site) as ledger:
                    record_extraction(
                        ledger,
                        tenant_id=site,
                        querying_tenant_id=requesting_tenant,
                        actor_id=actor_id,
                        epsilon=query.epsilon,
                        query_fingerprint=query.fingerprint(),
                    )
            except (InboundBudgetExhausted, SiteNotParticipating):
                # A site that cannot or will not answer is skipped, not fatal.
                # Failing the whole query would let one exhausted lab deny the
                # consortium, and would disclose that lab's ledger state to
                # every querier through the error.
                #
                # Reported as `unavailable`, NOT as `suppressed`. An earlier
                # version reused the suppression flag here and defended it as
                # "already an expected per-site outcome". That was wrong in
                # two ways.
                #
                # First, it made one field mean three different things: cohort
                # below threshold, inbound budget exhausted, or withdrawn
                # consent. Only the first is a DP release; the other two are
                # administrative and carry no noise. Collapsing them puts an
                # unprotected signal on a channel whose privacy analysis covers
                # only the protected one.
                #
                # Second, the three were distinguishable anyway. Withdrawal
                # drops the site from `sites` entirely, and the other two
                # separate on whether the inbound ledger moved -- a value
                # `/federation/participants` publishes. So the conflation hid
                # nothing and cost the response its precision.
                #
                # No epsilon is recorded for this site: nothing was read, so
                # nothing was disclosed, so nothing is owed. Charging for an
                # unread site inflates the reported total and makes the
                # accounting describe work that never happened.
                contributions.append(
                    SiteContribution(tenant_id=site, status=SiteStatus.UNAVAILABLE)
                )
                continue

            true_count = _count_matching_records(
                session, tenant_id=site, gene=query.gene
            )
            # Each site privatizes its own count before it leaves the site.
            # The exact value is never held outside this loop iteration.
            noisy = privatize_count(true_count, epsilon=query.epsilon)
            per_site.append(noisy)
            contributions.append(
                SiteContribution(
                    tenant_id=site,
                    status=(
                        SiteStatus.SUPPRESSED
                        if noisy.suppressed
                        else SiteStatus.CONTRIBUTED
                    ),
                )
            )

        # Restore the requester's tenant: the loop rebound the session to each
        # source lab in turn, and anything after this point (including the
        # session commit) must not run under the last site's context.
        set_tenant_context(session.connection(), requesting_tenant)

        combined = combine_federated_counts(per_site)

        logger.info(
            "federated cohort query: actor=%s tenant=%s fingerprint=%s "
            "sites=%d contributing=%d epsilon_charged=%.3f remaining=%.3f",
            actor_id,
            requesting_tenant,
            query.fingerprint()[:12],
            len(sites),
            sum(1 for c in contributions if c.status is SiteStatus.CONTRIBUTED),
            total_cost,
            remaining,
        )

        # Interval derived from the per-site scales that actually contributed.
        # Independent variances add, so a federated total is necessarily less
        # precise than any single site's answer.
        #
        # Note what this couples: suppression is decided from each site's TRUE
        # count, so the number of contributing sites -- and therefore the
        # reported tolerance -- is data-dependent. Interval width is an
        # invertible function of `sites_contributing` (at eps=0.1: +/-42.4 for
        # two sites, +/-67.0 for five).
        #
        # That is not a new disclosure: `sites_contributing` is already
        # returned in plaintext below, deliberately, so an analyst knows how
        # much of the consortium answered. But it does mean the interval is not
        # purely a function of public parameters, and anyone who later tries to
        # hide `sites_contributing` while keeping the interval would be
        # leaking it anyway.
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
            sites_contributing=sum(1 for c in contributions if c.status is SiteStatus.CONTRIBUTED),
            epsilon_spent=total_cost,
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
