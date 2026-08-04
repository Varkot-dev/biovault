"""Federated cohort discovery endpoints.

These are the only endpoints that return information derived from other labs'
data, and they return exclusively differentially private aggregates. No record,
identifier, or exact count crosses a tenant boundary.

Authorization here is deliberately different from the rest of the API. Every
other endpoint asks "may this principal read this resource?" and
`authz.policy.decide()` answers no for anything cross-tenant. That answer stays
correct — a federated *aggregate* is not record access, and is governed by the
privacy budget instead.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request, status

from biovault.api.dependencies import CurrentPrincipal, TenantSession
from biovault.api.rate_limit import limiter
from biovault.audit.recorder import authorize
from biovault.authz.policy import Action, ResourceRef
from biovault.config import get_settings
from biovault.db.rls import set_tenant_context
from biovault.db.session import untenanted_session
from biovault.federation.accuracy import (
    DEFAULT_ALPHA,
    MAX_ALPHA,
    MIN_ALPHA,
    epsilon_to_tolerance,
    federated_tolerance,
)
from biovault.federation.budget import DEFAULT_TOTAL_EPSILON, BudgetExhausted
from biovault.federation.cohort import (
    CohortQuery,
    FederatedCohortResult,
    budget_status,
    run_federated_cohort_query,
)
from biovault.federation.consent import (
    extracted_epsilon,
    inbound_limit_for,
    participating_sites,
)
from biovault.federation.privacy import MAX_EPSILON, MIN_EPSILON, PrivacyError

router = APIRouter(prefix="/federation", tags=["federation"])


@router.post("/cohort-count", response_model=FederatedCohortResult)
@limiter.limit(lambda: get_settings().rate_limit)
def federated_cohort_count(
    request: Request,
    query: CohortQuery,
    principal: CurrentPrincipal,
    session: TenantSession,
) -> FederatedCohortResult:
    """Count matching records across all labs, differentially privately.

    The caller must hold QUERY_FEDERATED, a capability distinct from READ.
    Auditors and read-only principals do not hold it, so federation cannot be
    used as a side channel to reach aggregates their role denies them.

    Returns 429 when the privacy budget is exhausted. That status is chosen
    deliberately over 403: exhaustion is a rate/quota condition that will
    resolve as entries age out of the window, not an authorization failure the
    caller could fix by obtaining different permissions.
    """
    decision = authorize(
        session,
        principal=principal,
        action=Action.QUERY_FEDERATED,
        resource=ResourceRef(tenant_id=principal.tenant_id),
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="not found"
        )

    try:
        return run_federated_cohort_query(
            query=query,
            requesting_tenant=principal.tenant_id,
            actor_id=principal.user_id,
        )
    except BudgetExhausted as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="privacy budget exhausted for this tenant",
        ) from exc
    except PrivacyError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid privacy parameters"
        ) from exc


@router.get("/precision")
@limiter.limit(lambda: get_settings().rate_limit)
def precision_preview(
    request: Request,
    principal: CurrentPrincipal,
    session: TenantSession,
    epsilon: float = Query(default=0.1, ge=MIN_EPSILON, le=MAX_EPSILON),
    alpha: float = Query(default=DEFAULT_ALPHA, ge=MIN_ALPHA, le=MAX_ALPHA),
    sites: int = Query(default=3, ge=1, le=50),
) -> dict[str, float]:
    """How precise would an answer be at this epsilon, before spending any?

    Costs no budget: the tolerance depends only on epsilon and the number of
    contributing sites, never on the data. An analyst can therefore size a
    study up front instead of discovering mid-study that every answer is too
    noisy to publish — which would burn budget producing nothing.
    """
    decision = authorize(
        session,
        principal=principal,
        action=Action.QUERY_FEDERATED,
        resource=ResourceRef(tenant_id=principal.tenant_id),
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    try:
        single = epsilon_to_tolerance(epsilon, alpha)
        combined = federated_tolerance([1.0 / epsilon] * sites, alpha)
    except PrivacyError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid privacy parameters"
        ) from exc

    return {
        "epsilon": epsilon,
        "confidence": 1.0 - alpha,
        "single_site_tolerance": round(single, 2),
        "federated_tolerance": round(combined, 2),
        "sites": float(sites),
        # A federated query costs epsilon PER SITE, so affordability divides by
        # epsilon * sites. Dividing by epsilon alone would overstate the number
        # of queries by the site multiplier -- telling an analyst they can
        # afford ten studies when the budget covers three, which is exactly the
        # kind of planning error this endpoint exists to prevent.
        "queries_affordable": float(int(DEFAULT_TOTAL_EPSILON / (epsilon * sites))),
    }



@router.get("/budget")
@limiter.limit(lambda: get_settings().rate_limit)
def get_budget(
    request: Request,
    principal: CurrentPrincipal,
    session: TenantSession,
) -> dict[str, float]:
    """Report the caller's tenant's remaining privacy budget.

    Visible to the tenant that owns it so analysts can plan queries rather
    than discovering exhaustion mid-study. Other tenants' budgets are not
    exposed: query volume reveals research direction.
    """
    decision = authorize(
        session,
        principal=principal,
        action=Action.QUERY_FEDERATED,
        resource=ResourceRef(tenant_id=principal.tenant_id),
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="not found"
        )

    return budget_status(tenant_id=principal.tenant_id)


@router.get("/participants")
@limiter.limit(lambda: get_settings().rate_limit)
def get_participants(
    request: Request,
    principal: CurrentPrincipal,
    session: TenantSession,
) -> dict[str, object]:
    """List participating sites and how much may still be extracted from each.

    Gated on QUERY_FEDERATED rather than READ, matching the other endpoints
    here: this describes the federation surface, not any lab's records.

    ## What this deliberately discloses, and why it is safe

    Participation and remaining inbound allowance are shown for every site, not
    just the caller's. Both are already implied by behaviour an analyst can
    observe without this endpoint — a non-participating site is absent from
    `contributions` in every result, and an exhausted site starts being refused
    — so publishing them adds no disclosure while making the consortium's state
    legible instead of something analysts infer from failures.

    It is also the information an analyst needs to plan honestly: knowing a
    site is nearly exhausted before spending outbound budget on a query that
    will return a thinner cohort than expected is strictly better than
    discovering it afterwards, with the budget already gone.

    Note the asymmetry with `/budget`, which exposes only the caller's own
    outbound budget. That restriction stands: outbound spend reveals how much
    querying a lab is doing, which leaks its research direction. Inbound
    allowance reveals how much has been *taken from* a lab in aggregate, which
    is a property of the consortium's demand on that lab rather than of any
    lab's own research programme, and the per-querier breakdown that would leak
    research direction is not returned.
    """
    decision = authorize(
        session,
        principal=principal,
        action=Action.QUERY_FEDERATED,
        resource=ResourceRef(tenant_id=principal.tenant_id),
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="not found"
        )

    participants: list[dict[str, object]] = []
    with untenanted_session() as ledger_session:
        sites = participating_sites(ledger_session)
        for site in sites:
            # The inbound ledger is scoped to the site the epsilon was taken
            # from, so context must be rebound per site. Reading it under the
            # caller's tenant would match zero rows and report every site as
            # having a full allowance -- telling analysts that exhausted sites
            # were untouched, which is the most misleading answer available.
            set_tenant_context(ledger_session.connection(), site)
            ceiling = inbound_limit_for(ledger_session, tenant_id=site)
            extracted = extracted_epsilon(ledger_session, tenant_id=site)
            participants.append(
                {
                    "tenant_id": site,
                    "participating": True,
                    "inbound_limit": round(ceiling, 3),
                    "inbound_extracted": round(extracted, 3),
                    "inbound_remaining": round(max(0.0, ceiling - extracted), 3),
                }
            )

    return {
        "sites": len(participants),
        "participants": participants,
    }
