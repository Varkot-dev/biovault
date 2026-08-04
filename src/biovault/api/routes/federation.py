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
        "queries_affordable": float(int(DEFAULT_TOTAL_EPSILON / epsilon)),
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
