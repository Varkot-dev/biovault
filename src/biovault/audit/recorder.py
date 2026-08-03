"""Audit recording for access decisions.

The compliance requirement is that *every* access decision — granted and
denied — leaves a record. The design problem is that "remember to log" is a
convention, and conventions get skipped under deadline.

`authorize()` solves this by fusing the two operations: it calls the policy and
writes the audit row, then returns the decision. There is no way to obtain a
decision through this function without a row being written, and endpoints have
no reason to call `decide()` directly. `test_endpoints_do_not_call_decide_directly`
enforces that they don't.

Denials are logged at least as carefully as grants: a repeated pattern of
denied cross-tenant reads is exactly the signal an intrusion investigation
needs, and it is invisible if only successes are recorded.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from biovault.authz.policy import Action, Decision, Principal, ResourceRef, decide
from biovault.models.tables import AuditEntry

logger = logging.getLogger(__name__)

_RESOURCE_DATASET = "dataset"
_RESOURCE_RECORD = "record"
_RESOURCE_TENANT = "tenant"


def _resource_type(resource: ResourceRef) -> str:
    if resource.record_id is not None:
        return _RESOURCE_RECORD
    if resource.dataset_id is not None:
        return _RESOURCE_DATASET
    return _RESOURCE_TENANT


def _resource_id(resource: ResourceRef) -> str | None:
    return resource.record_id or resource.dataset_id


def authorize(
    session: Session,
    *,
    principal: Principal,
    action: Action,
    resource: ResourceRef,
) -> Decision:
    """Decide whether an action is permitted, and record the decision.

    This is the only entry point endpoints should use. Calling
    `policy.decide()` directly would produce an unaudited decision.

    The audit row is written against the *principal's* tenant, not the
    resource's. On a denied cross-tenant attempt those differ, and the record
    belongs in the log of the lab whose user made the attempt — that is the
    lab whose auditor needs to see it. Writing it to the target tenant would
    also be blocked by RLS, silently losing exactly the events that matter
    most.
    """
    decision = decide(principal=principal, action=action, resource=resource)

    session.add(
        AuditEntry(
            tenant_id=principal.tenant_id,
            actor_id=principal.user_id,
            actor_role=principal.role.value,
            action=action.value,
            resource_type=_resource_type(resource),
            resource_id=_resource_id(resource),
            allowed=decision.allowed,
            reason=decision.reason,
        )
    )
    session.flush()

    if not decision.allowed:
        # Denials are logged at WARNING so they surface in operational
        # dashboards without requiring a database query.
        logger.warning(
            "access denied: actor=%s tenant=%s action=%s resource=%s reason=%s",
            principal.user_id,
            principal.tenant_id,
            action.value,
            _resource_id(resource),
            decision.reason,
        )

    return decision
