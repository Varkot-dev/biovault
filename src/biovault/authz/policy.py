"""Central authorization policy — the single source of access decisions.

Every access decision in BioVault is made by `decide()`. Endpoints call it and
obey the result; they never re-derive policy from a role. A `grep` for
`role ==` outside this module should return nothing, and CI enforces that
(see `tests/security/test_policy_is_central.py`).

Structure of a decision, evaluated as an ordered gate chain:

    1. tenant   — is the principal in the resource's lab at all?
    2. action   — does the role hold this capability?
    3. dataset  — does the principal have this specific dataset?
    4. record   — does the record's sensitivity require extra clearance?

Each gate can only deny. Reaching the end is the sole path to a grant, so a
new action added to the `Action` enum without a matching capability entry is
denied by construction rather than accidentally permitted.
"""

from __future__ import annotations

from enum import StrEnum, unique
from typing import Final

from pydantic import BaseModel, ConfigDict, Field


@unique
class Role(StrEnum):
    """Roles a principal may hold within one tenant."""

    LAB_ADMIN = "lab_admin"
    RESEARCHER = "researcher"
    AUDITOR = "auditor"
    READ_ONLY = "read_only"


@unique
class Action(StrEnum):
    """Operations that can be attempted against a resource."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    MANAGE_GRANTS = "manage_grants"
    READ_AUDIT = "read_audit"
    # Federated aggregate queries spanning tenants. Deliberately distinct from
    # READ: it returns only differentially private aggregates, never records,
    # and is governed by the privacy budget rather than by dataset grants.
    # Modelling it as READ would have been wrong in both directions — it would
    # require a dataset grant the query does not need, and it would imply
    # record access the query must never confer.
    QUERY_FEDERATED = "query_federated"


class Principal(BaseModel):
    """The authenticated actor. Immutable.

    Built from verified token claims only. Never from request-supplied fields:
    accepting a client-declared role or tenant is the privilege-escalation
    vulnerability this whole module exists to prevent.
    """

    model_config = ConfigDict(frozen=True)

    user_id: str
    tenant_id: str
    role: Role
    dataset_grants: frozenset[str] = Field(default_factory=frozenset)
    phi_cleared: bool = False


class ResourceRef(BaseModel):
    """The thing being acted upon. Immutable.

    Always loaded from the database before the check. Trusting a
    client-supplied `tenant_id` here would make cross-tenant denial trivially
    bypassable by lying about which lab owns the record.
    """

    model_config = ConfigDict(frozen=True)

    tenant_id: str
    dataset_id: str | None = None
    record_id: str | None = None
    contains_phi: bool = False


class Decision(BaseModel):
    """Outcome of an authorization check. Immutable.

    `reason` is mandatory. Every decision — granted or denied — is written to
    the audit log, and a compliance record with no stated reason is not worth
    keeping.
    """

    model_config = ConfigDict(frozen=True)

    allowed: bool
    reason: str


# Capabilities per role. A role may attempt only the actions listed here;
# holding the capability is necessary but not sufficient, since the dataset
# and record gates run afterwards.
_CAPABILITIES: Final[dict[Role, frozenset[Action]]] = {
    Role.LAB_ADMIN: frozenset(
        {
            Action.READ,
            Action.WRITE,
            Action.DELETE,
            Action.MANAGE_GRANTS,
            Action.QUERY_FEDERATED,
        }
    ),
    Role.RESEARCHER: frozenset({Action.READ, Action.WRITE, Action.QUERY_FEDERATED}),
    Role.AUDITOR: frozenset({Action.READ_AUDIT}),
    Role.READ_ONLY: frozenset({Action.READ}),
}

# Roles exempt from per-dataset grants *within their own tenant*. A lab admin
# administers their whole lab; this never widens tenant scope, because the
# tenant gate has already run by the time this is consulted.
_TENANT_WIDE_ROLES: Final[frozenset[Role]] = frozenset({Role.LAB_ADMIN, Role.AUDITOR})

# Actions that operate on the tenant rather than one dataset, and so are not
# subject to the dataset-grant gate.
_TENANT_SCOPED_ACTIONS: Final[frozenset[Action]] = frozenset(
    {Action.READ_AUDIT, Action.QUERY_FEDERATED}
)

# Actions that expose record contents, and so are subject to PHI clearance.
_CONTENT_ACTIONS: Final[frozenset[Action]] = frozenset({Action.READ, Action.WRITE})


def decide(*, principal: Principal, action: Action, resource: ResourceRef) -> Decision:
    """Return whether `principal` may perform `action` on `resource`.

    Default deny: every gate below can only deny, and a grant is returned only
    by falling through all of them.

    This function is pure — no I/O, no clock, no database. That is what makes
    the policy exhaustively testable, and it is why audit logging happens at
    the caller rather than here.
    """
    # Gate 1: tenant isolation. First and unconditional, including for
    # lab_admin. This is the "3 isolated research labs" guarantee.
    if principal.tenant_id != resource.tenant_id:
        return Decision(
            allowed=False,
            reason=(
                f"cross-tenant access denied: principal in tenant "
                f"{principal.tenant_id!r}, resource in tenant {resource.tenant_id!r}"
            ),
        )

    # Gate 2: role capability. Unknown roles yield an empty capability set.
    if action not in _CAPABILITIES.get(principal.role, frozenset()):
        return Decision(
            allowed=False,
            reason=f"role {principal.role.value!r} lacks capability {action.value!r}",
        )

    # Gate 3: dataset grant.
    if action not in _TENANT_SCOPED_ACTIONS and principal.role not in _TENANT_WIDE_ROLES:
        if resource.dataset_id is None:
            return Decision(
                allowed=False,
                reason=f"action {action.value!r} requires a dataset-scoped resource",
            )
        if resource.dataset_id not in principal.dataset_grants:
            return Decision(
                allowed=False,
                reason=(
                    f"no grant for dataset {resource.dataset_id!r} "
                    f"held by user {principal.user_id!r}"
                ),
            )

    # Gate 4: record sensitivity. Applies to every role, including lab_admin.
    if resource.contains_phi and action in _CONTENT_ACTIONS and not principal.phi_cleared:
        return Decision(
            allowed=False,
            reason=(
                f"record contains PHI and user {principal.user_id!r} "
                f"lacks PHI clearance"
            ),
        )

    return Decision(
        allowed=True,
        reason=(
            f"role {principal.role.value!r} permits {action.value!r} "
            f"in tenant {resource.tenant_id!r}"
        ),
    )
