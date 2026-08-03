"""Audit log completeness and immutability.

Compliance requires every access decision to leave a record. These tests check
three separable things:

1. Grants are recorded.
2. Denials are recorded — the case that gets forgotten, and the one an
   intrusion investigation actually needs.
3. The record cannot be altered afterwards, enforced by PostgreSQL rather than
   by application convention.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from sqlalchemy import select, text

from biovault.audit.recorder import authorize
from biovault.authz.policy import Action, Principal, ResourceRef, Role
from biovault.models.tables import AuditEntry

pytestmark = [pytest.mark.security, pytest.mark.integration]

BROAD = "lab-broad"
SANGER = "lab-sanger"


@pytest.fixture
def actor_id() -> str:
    """A unique actor per test.

    The audit table is append-only by design, so rows written by earlier tests
    (and by the API suite) persist. Scoping each test to its own actor makes
    the assertions independent of execution order without weakening the
    immutability guarantee that makes cleanup impossible.
    """
    import uuid

    return f"u-audit-test-{uuid.uuid4().hex[:12]}"


def researcher(
    actor: str,
    tenant: str = BROAD,
    grants: frozenset[str] = frozenset({"ds-1"}),
) -> Principal:
    return Principal(
        user_id=actor, tenant_id=tenant, role=Role.RESEARCHER, dataset_grants=grants
    )


def _entries(session, actor: str) -> list[AuditEntry]:
    return list(
        session.execute(
            select(AuditEntry).where(AuditEntry.actor_id == actor)
        ).scalars().all()
    )


def test_granted_access_is_recorded(owner_session, actor_id: str) -> None:
    decision = authorize(
        owner_session,
        principal=researcher(actor_id),
        action=Action.READ,
        resource=ResourceRef(tenant_id=BROAD, dataset_id="ds-1"),
    )
    assert decision.allowed is True

    entries = _entries(owner_session, actor_id)
    assert len(entries) == 1
    assert entries[0].allowed is True
    assert entries[0].action == "read"
    assert entries[0].reason


def test_denied_access_is_recorded(owner_session, actor_id: str) -> None:
    """The case that matters most and is most often missed."""
    decision = authorize(
        owner_session,
        principal=researcher(actor_id),
        action=Action.DELETE,
        resource=ResourceRef(tenant_id=BROAD, dataset_id="ds-1"),
    )
    assert decision.allowed is False

    entries = _entries(owner_session, actor_id)
    assert len(entries) == 1
    assert entries[0].allowed is False
    assert "capability" in entries[0].reason


def test_cross_tenant_denial_is_recorded_under_the_principals_tenant(
    owner_session, actor_id: str
) -> None:
    """Attribution matters for two reasons.

    Ownership: the attempting user's own lab needs to see the probe.
    Mechanics: writing the row under the *target* tenant would be blocked by
    the RLS WITH CHECK policy, silently discarding the intrusion evidence.
    """
    authorize(
        owner_session,
        principal=researcher(actor_id, tenant=BROAD),
        action=Action.READ,
        resource=ResourceRef(tenant_id=SANGER, dataset_id="ds-sanger-onco-1"),
    )

    entry = _entries(owner_session, actor_id)[0]
    assert entry.allowed is False
    assert entry.tenant_id == BROAD, "audit row must belong to the attempting lab"
    assert "cross-tenant" in entry.reason


def test_every_decision_records_actor_action_resource_and_reason(
    owner_session, actor_id: str
) -> None:
    """The four fields the spec names as required."""
    authorize(
        owner_session,
        principal=researcher(actor_id),
        action=Action.READ,
        resource=ResourceRef(tenant_id=BROAD, dataset_id="ds-1", record_id="rec-9"),
    )
    entry = _entries(owner_session, actor_id)[0]

    assert entry.actor_id == actor_id
    assert entry.actor_role == "researcher"
    assert entry.action == "read"
    assert entry.resource_type == "record"
    assert entry.resource_id == "rec-9"
    assert entry.reason
    assert entry.occurred_at is not None


@pytest.mark.parametrize("action", list(Action))
def test_every_action_type_produces_an_entry(
    owner_session, actor_id: str, action: Action
) -> None:
    """No action may slip through unaudited, whatever its outcome."""
    authorize(
        owner_session,
        principal=researcher(actor_id),
        action=action,
        resource=ResourceRef(tenant_id=BROAD, dataset_id="ds-1"),
    )
    assert len(_entries(owner_session, actor_id)) == 1


def test_repeated_attempts_each_produce_a_row(owner_session, actor_id: str) -> None:
    """A brute-force pattern must be visible as repeated denials."""
    for _ in range(5):
        authorize(
            owner_session,
            principal=researcher(actor_id, tenant=BROAD),
            action=Action.READ,
            resource=ResourceRef(tenant_id=SANGER, dataset_id="ds-sanger-onco-1"),
        )
    entries = _entries(owner_session, actor_id)
    assert len(entries) == 5
    assert all(e.allowed is False for e in entries)


def test_authorize_returns_the_same_decision_as_the_policy(
    owner_session, actor_id: str
) -> None:
    """Auditing must not alter the decision it records."""
    from biovault.authz.policy import decide

    principal = researcher(actor_id)
    resource = ResourceRef(tenant_id=BROAD, dataset_id="ds-1")

    audited = authorize(
        owner_session, principal=principal, action=Action.READ, resource=resource
    )
    direct = decide(principal=principal, action=Action.READ, resource=resource)

    assert audited.allowed == direct.allowed
    assert audited.reason == direct.reason


# --- Immutability -----------------------------------------------------------


def test_app_role_cannot_update_audit_entries(app_connection, set_tenant) -> None:
    """Enforced by GRANT, so a compromised application cannot rewrite history."""
    set_tenant(BROAD)
    app_connection.execute(
        text(
            "INSERT INTO audit_entries "
            "(id, tenant_id, actor_id, actor_role, action, resource_type, "
            " resource_id, allowed, reason) "
            "VALUES ('audit-update-probe', :t, 'u-1', 'researcher', 'read', "
            "        'dataset', 'ds-1', false, 'original reason')"
        ).bindparams(t=BROAD)
    )
    with pytest.raises(Exception) as exc:
        app_connection.execute(
            text("UPDATE audit_entries SET allowed = true WHERE id = 'audit-update-probe'")
        )
    assert "permission denied" in str(exc.value).lower()


def test_app_role_cannot_delete_audit_entries(app_connection, set_tenant) -> None:
    set_tenant(BROAD)
    app_connection.execute(
        text(
            "INSERT INTO audit_entries "
            "(id, tenant_id, actor_id, actor_role, action, resource_type, "
            " resource_id, allowed, reason) "
            "VALUES ('audit-delete-probe', :t, 'u-1', 'researcher', 'read', "
            "        'dataset', 'ds-1', false, 'reason')"
        ).bindparams(t=BROAD)
    )
    with pytest.raises(Exception) as exc:
        app_connection.execute(
            text("DELETE FROM audit_entries WHERE id = 'audit-delete-probe'")
        )
    assert "permission denied" in str(exc.value).lower()


def test_audit_entries_are_tenant_isolated(app_connection, set_tenant) -> None:
    """An auditor must not read another lab's audit trail."""
    set_tenant(BROAD)
    app_connection.execute(
        text(
            "INSERT INTO audit_entries "
            "(id, tenant_id, actor_id, actor_role, action, resource_type, "
            " resource_id, allowed, reason) "
            "VALUES ('audit-iso-probe', :t, 'u-1', 'auditor', 'read', "
            "        'dataset', 'ds-1', true, 'reason')"
        ).bindparams(t=BROAD)
    )

    set_tenant(SANGER)
    visible = app_connection.execute(
        text("SELECT count(*) FROM audit_entries WHERE id = 'audit-iso-probe'")
    ).scalar_one()
    assert visible == 0


# --- Structural: auditing cannot be bypassed --------------------------------


@pytest.mark.security
def test_api_modules_do_not_call_decide_directly() -> None:
    """API code must route through `authorize`, which audits.

    Calling `policy.decide()` from an endpoint would produce a correct but
    *unaudited* decision — passing every authorization test while silently
    breaking the compliance requirement. AST inspection catches that.
    """
    api_root = Path(__file__).resolve().parents[2] / "src" / "biovault" / "api"
    if not api_root.exists():
        pytest.skip("API package not present yet")

    offenders: list[str] = []
    for path in api_root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = (
                    func.id
                    if isinstance(func, ast.Name)
                    else func.attr
                    if isinstance(func, ast.Attribute)
                    else None
                )
                if name == "decide":
                    offenders.append(f"{path.name}:{node.lineno}")

    assert not offenders, (
        "API modules must call audit.recorder.authorize, not policy.decide "
        f"directly (unaudited decisions): {offenders}"
    )
