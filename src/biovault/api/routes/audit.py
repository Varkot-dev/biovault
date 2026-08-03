"""Audit log endpoint.

Reading the audit trail is a distinct capability held only by `auditor`. A
researcher who could read the log would learn which datasets exist and who
touched them — metadata that is itself sensitive.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request, status
from sqlalchemy import select

from biovault.api.dependencies import CurrentPrincipal, TenantSession
from biovault.api.rate_limit import limiter
from biovault.audit.recorder import authorize
from biovault.authz.policy import Action, ResourceRef
from biovault.config import get_settings
from biovault.models.tables import AuditEntry
from biovault.schemas.datasets import AuditEntryResponse

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=list[AuditEntryResponse])
@limiter.limit(lambda: get_settings().rate_limit)
def list_audit_entries(
    request: Request,
    principal: CurrentPrincipal,
    session: TenantSession,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[AuditEntryResponse]:
    """Return this tenant's audit entries, newest first.

    RLS scopes the query to the caller's tenant, so an auditor cannot read
    another lab's trail even if the policy check were bypassed.
    """
    decision = authorize(
        session,
        principal=principal,
        action=Action.READ_AUDIT,
        resource=ResourceRef(tenant_id=principal.tenant_id),
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="audit log not found"
        )

    rows = (
        session.execute(
            select(AuditEntry)
            .order_by(AuditEntry.occurred_at.desc())
            .limit(limit)
            .offset(offset)
        )
        .scalars()
        .all()
    )

    return [
        AuditEntryResponse(
            id=row.id,
            actor_id=row.actor_id,
            actor_role=row.actor_role,
            action=row.action,
            resource_type=row.resource_type,
            resource_id=row.resource_id,
            allowed=row.allowed,
            reason=row.reason,
            occurred_at=row.occurred_at,
        )
        for row in rows
    ]
