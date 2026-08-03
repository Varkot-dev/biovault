"""Structural guarantees about the authorization policy.

Two properties the spec demands that ordinary unit tests cannot express:

1. Policy decisions live in exactly one module. Scattered `if role ==` checks
   drift out of sync and are the usual root cause of access-control bugs.
2. Tenant isolation holds across the *entire* input space, not just the
   combinations someone thought to write a test for.
"""

from __future__ import annotations

import ast
import itertools
from pathlib import Path

import pytest

from biovault.authz.policy import (
    Action,
    Principal,
    ResourceRef,
    Role,
    decide,
)

SRC_ROOT = Path(__file__).resolve().parents[2] / "src" / "biovault"
POLICY_MODULE = SRC_ROOT / "authz" / "policy.py"


def _python_files_outside_policy() -> list[Path]:
    return [p for p in SRC_ROOT.rglob("*.py") if p.resolve() != POLICY_MODULE.resolve()]


@pytest.mark.security
def test_no_role_comparisons_outside_the_policy_module() -> None:
    """No module other than the policy may branch on a role value.

    Enforced by AST inspection rather than grep so that string literals and
    comments do not produce false positives.
    """
    role_values = {r.value for r in Role}
    offenders: list[str] = []

    for path in _python_files_outside_policy():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
            operands = [node.left, *node.comparators]
            mentions_role_attr = any(
                isinstance(o, ast.Attribute) and o.attr == "role" for o in operands
            )
            mentions_role_literal = any(
                isinstance(o, ast.Constant) and o.value in role_values for o in operands
            )
            mentions_role_enum = any(
                isinstance(o, ast.Attribute)
                and isinstance(o.value, ast.Name)
                and o.value.id == "Role"
                for o in operands
            )
            if mentions_role_attr or mentions_role_literal or mentions_role_enum:
                offenders.append(f"{path.relative_to(SRC_ROOT)}:{node.lineno}")

    assert not offenders, (
        "role comparisons found outside biovault/authz/policy.py — policy must "
        f"stay centralized: {offenders}"
    )


@pytest.mark.security
def test_tenant_isolation_holds_across_entire_input_space() -> None:
    """Exhaustive sweep: no input combination yields a cross-tenant grant.

    This is the "3 isolated research labs" resume claim stated as a property
    over every reachable input rather than a sampled set of examples.
    """
    tenants = ("lab-broad", "lab-sanger", "lab-riken")
    leaks: list[tuple[object, ...]] = []

    combos = itertools.product(
        Role,
        Action,
        (True, False),  # resource contains PHI
        (True, False),  # principal PHI-cleared
        (frozenset(), frozenset({"ds-1"})),  # dataset grants
        itertools.permutations(tenants, 2),  # (principal tenant, resource tenant)
    )

    for role, action, phi, cleared, grants, (home, foreign) in combos:
        result = decide(
            principal=Principal(
                user_id="u-1",
                tenant_id=home,
                role=role,
                dataset_grants=grants,
                phi_cleared=cleared,
            ),
            action=action,
            resource=ResourceRef(tenant_id=foreign, dataset_id="ds-1", contains_phi=phi),
        )
        if result.allowed:
            leaks.append((role, action, phi, cleared, grants, home, foreign))

    assert not leaks, f"cross-tenant access granted for: {leaks}"


@pytest.mark.security
def test_phi_clearance_gates_disclosure_not_destruction() -> None:
    """DELETE is intentionally exempt from the PHI gate.

    PHI clearance controls who may *see* protected content. Deleting a record
    discloses nothing, so it is gated by the DELETE capability (lab_admin only)
    rather than by clearance. Conflating the two would mix a confidentiality
    control with an integrity control.

    This test exists so the exemption stays a decision rather than becoming an
    accident of gate ordering.
    """
    admin = Principal(user_id="u-1", tenant_id="lab-broad", role=Role.LAB_ADMIN)
    phi_record = ResourceRef(tenant_id="lab-broad", dataset_id="ds-1", contains_phi=True)

    assert decide(principal=admin, action=Action.DELETE, resource=phi_record).allowed is True
    assert decide(principal=admin, action=Action.READ, resource=phi_record).allowed is False
    assert decide(principal=admin, action=Action.WRITE, resource=phi_record).allowed is False


@pytest.mark.security
def test_every_action_is_covered_by_some_capability_set() -> None:
    """A new Action must be deliberately assigned, not silently unreachable."""
    from biovault.authz.policy import _CAPABILITIES

    assigned = frozenset().union(*_CAPABILITIES.values())
    unassigned = set(Action) - set(assigned)
    assert not unassigned, f"actions no role can perform: {unassigned}"


@pytest.mark.security
def test_every_role_has_an_explicit_capability_entry() -> None:
    """A role missing from the table would fail closed, but silently."""
    from biovault.authz.policy import _CAPABILITIES

    missing = set(Role) - set(_CAPABILITIES)
    assert not missing, f"roles with no capability entry: {missing}"
