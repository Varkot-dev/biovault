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

from fastapi import APIRouter, HTTPException, Request, status

from biovault.api.dependencies import CurrentPrincipal, TenantSession
from biovault.api.rate_limit import limiter
from biovault.audit.recorder import authorize
from biovault.authz.policy import Action, ResourceRef
from biovault.config import get_settings
from biovault.federation.budget import BudgetExhausted
from biovault.federation.cohort import (
    CohortQuery,
    FederatedCohortResult,
    budget_status,
    run_federated_cohort_query,
)
from biovault.federation.privacy import PrivacyError

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
