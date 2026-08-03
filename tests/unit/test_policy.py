"""Unit tests for the central authorization policy.

Every access decision in BioVault flows through `decide()`. These tests are the
specification of what that function is allowed to permit. The negative cases
dominate deliberately: default-deny is only meaningful if the denials are
tested as carefully as the grants.
"""

from __future__ import annotations

import pytest

from biovault.authz.policy import (
    Action,
    Decision,
    Principal,
    ResourceRef,
    Role,
    decide,
)

LAB_A = "lab-broad"
LAB_B = "lab-sanger"
LAB_C = "lab-riken"

DATASET_A1 = "ds-a1"
DATASET_A2 = "ds-a2"
DATASET_B1 = "ds-b1"


def principal(
    role: Role,
    tenant: str = LAB_A,
    *,
    user_id: str = "u-1",
    dataset_grants: frozenset[str] = frozenset(),
) -> Principal:
    return Principal(
        user_id=user_id,
        tenant_id=tenant,
        role=role,
        dataset_grants=dataset_grants,
    )


def dataset(
    dataset_id: str = DATASET_A1,
    tenant: str = LAB_A,
    *,
    contains_phi: bool = False,
) -> ResourceRef:
    return ResourceRef(
        tenant_id=tenant,
        dataset_id=dataset_id,
        record_id=None,
        contains_phi=contains_phi,
    )


# --- Default deny -----------------------------------------------------------


def test_unknown_action_on_unknown_resource_is_denied() -> None:
    """The base case: nothing is permitted unless a rule says so."""
    result = decide(
        principal=principal(Role.READ_ONLY),
        action=Action.DELETE,
        resource=dataset(),
    )
    assert result.allowed is False


def test_every_decision_carries_a_reason() -> None:
    """Audit records are worthless without a reason; the type enforces one."""
    result = decide(
        principal=principal(Role.RESEARCHER, dataset_grants=frozenset({DATASET_A1})),
        action=Action.READ,
        resource=dataset(),
    )
    assert result.reason
    assert isinstance(result, Decision)


@pytest.mark.parametrize("role", list(Role))
def test_no_role_may_act_outside_its_tenant(role: Role) -> None:
    """Tenant isolation binds every role, including lab_admin.

    This is the single most important property in the system: the "3 research
    labs" claim is exactly this test passing for every role.
    """
    result = decide(
        principal=principal(role, tenant=LAB_A, dataset_grants=frozenset({DATASET_B1})),
        action=Action.READ,
        resource=dataset(DATASET_B1, tenant=LAB_B),
    )
    assert result.allowed is False
    assert "tenant" in result.reason.lower()


@pytest.mark.parametrize("role", list(Role))
@pytest.mark.parametrize("action", list(Action))
def test_cross_tenant_denied_for_every_role_action_pair(role: Role, action: Action) -> None:
    """Exhaustive cross-product: no (role, action) combination crosses tenants."""
    result = decide(
        principal=principal(role, tenant=LAB_A, dataset_grants=frozenset({DATASET_B1})),
        action=action,
        resource=dataset(DATASET_B1, tenant=LAB_B),
    )
    assert result.allowed is False


def test_third_tenant_is_also_isolated() -> None:
    """Isolation is not a two-party special case."""
    for source, target in ((LAB_A, LAB_C), (LAB_C, LAB_B), (LAB_B, LAB_C)):
        result = decide(
            principal=principal(Role.LAB_ADMIN, tenant=source),
            action=Action.READ,
            resource=dataset("ds-x", tenant=target),
        )
        assert result.allowed is False, f"{source} reached {target}"


# --- Researcher -------------------------------------------------------------


def test_researcher_reads_granted_dataset() -> None:
    result = decide(
        principal=principal(Role.RESEARCHER, dataset_grants=frozenset({DATASET_A1})),
        action=Action.READ,
        resource=dataset(DATASET_A1),
    )
    assert result.allowed is True


def test_researcher_cannot_read_ungranted_dataset_in_own_tenant() -> None:
    """Dataset-level enforcement: same lab is not sufficient."""
    result = decide(
        principal=principal(Role.RESEARCHER, dataset_grants=frozenset({DATASET_A1})),
        action=Action.READ,
        resource=dataset(DATASET_A2),
    )
    assert result.allowed is False
    assert "grant" in result.reason.lower()


def test_researcher_may_write_to_granted_dataset() -> None:
    result = decide(
        principal=principal(Role.RESEARCHER, dataset_grants=frozenset({DATASET_A1})),
        action=Action.WRITE,
        resource=dataset(DATASET_A1),
    )
    assert result.allowed is True


def test_researcher_cannot_delete() -> None:
    result = decide(
        principal=principal(Role.RESEARCHER, dataset_grants=frozenset({DATASET_A1})),
        action=Action.DELETE,
        resource=dataset(DATASET_A1),
    )
    assert result.allowed is False


def test_researcher_cannot_manage_grants() -> None:
    """Privilege escalation: a researcher granting themselves more access."""
    result = decide(
        principal=principal(Role.RESEARCHER, dataset_grants=frozenset({DATASET_A1})),
        action=Action.MANAGE_GRANTS,
        resource=dataset(DATASET_A1),
    )
    assert result.allowed is False


def test_researcher_cannot_read_audit_log() -> None:
    result = decide(
        principal=principal(Role.RESEARCHER, dataset_grants=frozenset({DATASET_A1})),
        action=Action.READ_AUDIT,
        resource=dataset(DATASET_A1),
    )
    assert result.allowed is False


# --- Lab admin --------------------------------------------------------------


def test_lab_admin_reads_any_dataset_in_own_tenant_without_explicit_grant() -> None:
    result = decide(
        principal=principal(Role.LAB_ADMIN),
        action=Action.READ,
        resource=dataset(DATASET_A2),
    )
    assert result.allowed is True


def test_lab_admin_may_delete_in_own_tenant() -> None:
    result = decide(
        principal=principal(Role.LAB_ADMIN),
        action=Action.DELETE,
        resource=dataset(DATASET_A1),
    )
    assert result.allowed is True


def test_lab_admin_may_manage_grants_in_own_tenant() -> None:
    result = decide(
        principal=principal(Role.LAB_ADMIN),
        action=Action.MANAGE_GRANTS,
        resource=dataset(DATASET_A1),
    )
    assert result.allowed is True


def test_lab_admin_cannot_delete_in_another_tenant() -> None:
    result = decide(
        principal=principal(Role.LAB_ADMIN, tenant=LAB_A),
        action=Action.DELETE,
        resource=dataset(DATASET_B1, tenant=LAB_B),
    )
    assert result.allowed is False


# --- Auditor ----------------------------------------------------------------


def test_auditor_may_read_audit_log() -> None:
    result = decide(
        principal=principal(Role.AUDITOR),
        action=Action.READ_AUDIT,
        resource=dataset(),
    )
    assert result.allowed is True


def test_auditor_cannot_read_dataset_contents() -> None:
    """Separation of duty: an auditor reviews access, not genomic data."""
    result = decide(
        principal=principal(Role.AUDITOR),
        action=Action.READ,
        resource=dataset(),
    )
    assert result.allowed is False


def test_auditor_cannot_write() -> None:
    result = decide(
        principal=principal(Role.AUDITOR),
        action=Action.WRITE,
        resource=dataset(),
    )
    assert result.allowed is False


def test_auditor_cannot_read_audit_log_of_another_tenant() -> None:
    result = decide(
        principal=principal(Role.AUDITOR, tenant=LAB_A),
        action=Action.READ_AUDIT,
        resource=dataset(tenant=LAB_B),
    )
    assert result.allowed is False


# --- Read-only --------------------------------------------------------------


def test_read_only_may_read_granted_dataset() -> None:
    result = decide(
        principal=principal(Role.READ_ONLY, dataset_grants=frozenset({DATASET_A1})),
        action=Action.READ,
        resource=dataset(DATASET_A1),
    )
    assert result.allowed is True


def test_read_only_cannot_write() -> None:
    result = decide(
        principal=principal(Role.READ_ONLY, dataset_grants=frozenset({DATASET_A1})),
        action=Action.WRITE,
        resource=dataset(DATASET_A1),
    )
    assert result.allowed is False


@pytest.mark.parametrize(
    "action", [Action.WRITE, Action.DELETE, Action.MANAGE_GRANTS, Action.READ_AUDIT]
)
def test_read_only_is_denied_every_mutating_action(action: Action) -> None:
    result = decide(
        principal=principal(Role.READ_ONLY, dataset_grants=frozenset({DATASET_A1})),
        action=action,
        resource=dataset(DATASET_A1),
    )
    assert result.allowed is False


# --- Record-level enforcement -----------------------------------------------


def test_phi_record_denied_to_researcher_without_phi_clearance() -> None:
    """Third enforcement level: record sensitivity, below dataset grants."""
    result = decide(
        principal=principal(Role.RESEARCHER, dataset_grants=frozenset({DATASET_A1})),
        action=Action.READ,
        resource=dataset(DATASET_A1, contains_phi=True),
    )
    assert result.allowed is False
    assert "phi" in result.reason.lower()


def test_phi_record_allowed_to_researcher_with_clearance() -> None:
    cleared = Principal(
        user_id="u-1",
        tenant_id=LAB_A,
        role=Role.RESEARCHER,
        dataset_grants=frozenset({DATASET_A1}),
        phi_cleared=True,
    )
    result = decide(
        principal=cleared,
        action=Action.READ,
        resource=dataset(DATASET_A1, contains_phi=True),
    )
    assert result.allowed is True


def test_phi_clearance_does_not_override_tenant_isolation() -> None:
    """Clearance is orthogonal to isolation; it must not become a bypass."""
    cleared = Principal(
        user_id="u-1",
        tenant_id=LAB_A,
        role=Role.LAB_ADMIN,
        dataset_grants=frozenset({DATASET_B1}),
        phi_cleared=True,
    )
    result = decide(
        principal=cleared,
        action=Action.READ,
        resource=dataset(DATASET_B1, tenant=LAB_B, contains_phi=True),
    )
    assert result.allowed is False


def test_phi_clearance_does_not_override_dataset_grants() -> None:
    cleared = Principal(
        user_id="u-1",
        tenant_id=LAB_A,
        role=Role.RESEARCHER,
        dataset_grants=frozenset(),
        phi_cleared=True,
    )
    result = decide(
        principal=cleared,
        action=Action.READ,
        resource=dataset(DATASET_A1, contains_phi=True),
    )
    assert result.allowed is False


# --- Immutability -----------------------------------------------------------


def test_principal_is_immutable() -> None:
    """A mutable principal could be escalated after the check but before use."""
    p = principal(Role.READ_ONLY)
    with pytest.raises((AttributeError, TypeError, ValueError)):
        p.role = Role.LAB_ADMIN  # type: ignore[misc]


def test_decision_is_immutable() -> None:
    result = decide(
        principal=principal(Role.LAB_ADMIN),
        action=Action.READ,
        resource=dataset(),
    )
    with pytest.raises((AttributeError, TypeError, ValueError)):
        result.allowed = True  # type: ignore[misc]


def test_resource_ref_is_immutable() -> None:
    r = dataset()
    with pytest.raises((AttributeError, TypeError, ValueError)):
        r.tenant_id = LAB_B  # type: ignore[misc]


# --- Exhaustiveness ---------------------------------------------------------


@pytest.mark.parametrize("role", list(Role))
@pytest.mark.parametrize("action", list(Action))
def test_decide_never_raises_for_any_role_action_pair(role: Role, action: Action) -> None:
    """A policy that throws is a policy that fails open at the call site."""
    result = decide(
        principal=principal(role, dataset_grants=frozenset({DATASET_A1})),
        action=action,
        resource=dataset(DATASET_A1),
    )
    assert isinstance(result.allowed, bool)
    assert result.reason
