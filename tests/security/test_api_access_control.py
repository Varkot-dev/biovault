"""End-to-end access-control tests against the HTTP API.

These exercise the full stack — token verification, policy, RLS, audit — as an
attacker would: by making requests. Covers the mandated IDOR and SQL-injection
cases, plus the information-leak boundary between 403 and 404.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from biovault.auth.tokens import issue_access_token
from biovault.authz.policy import Role

pytestmark = [pytest.mark.security, pytest.mark.integration]

BROAD = "lab-broad"
SANGER = "lab-sanger"
RIKEN = "lab-riken"

BROAD_DATASET = "ds-broad-cohort-1"
BROAD_DATASET_UNGRANTED = "ds-broad-cohort-2"
SANGER_DATASET = "ds-sanger-onco-1"
RIKEN_DATASET = "ds-riken-pop-1"


@pytest.fixture
def client(live_settings) -> TestClient:
    from biovault.api.main import app

    return TestClient(app, raise_server_exceptions=False)


def auth(
    *,
    user_id: str,
    tenant: str,
    role: Role,
    grants: frozenset[str] = frozenset(),
    phi_cleared: bool = False,
    settings=None,
) -> dict[str, str]:
    token = issue_access_token(
        subject=user_id,
        tenant_id=tenant,
        role=role,
        dataset_grants=grants,
        phi_cleared=phi_cleared,
        secret=settings.jwt_secret.get_secret_value(),
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        ttl_seconds=900,
    )
    return {"Authorization": f"Bearer {token}"}


# --- Authentication boundary ------------------------------------------------


@pytest.mark.parametrize("path", ["/datasets", "/audit"])
def test_unauthenticated_requests_are_rejected(client: TestClient, path: str) -> None:
    assert client.get(path).status_code == 401


@pytest.mark.parametrize(
    "header",
    ["", "Bearer", "Bearer ", "Basic abc", "bearer not-a-jwt", "abc.def.ghi"],
)
def test_malformed_authorization_headers_are_rejected(
    client: TestClient, header: str
) -> None:
    assert client.get("/datasets", headers={"Authorization": header}).status_code == 401


def test_health_endpoint_needs_no_authentication(client: TestClient) -> None:
    assert client.get("/health").status_code == 200


# --- MANDATED: IDOR on dataset identifiers ----------------------------------


def test_idor_cross_tenant_dataset_read_is_denied(client: TestClient, live_settings) -> None:
    """A lab-broad admin requests lab-sanger's dataset by its real id.

    This is the direct IDOR: a valid, authenticated caller substituting an
    identifier they were never granted.
    """
    headers = auth(
        user_id="u-broad-admin", tenant=BROAD, role=Role.LAB_ADMIN, settings=live_settings
    )
    response = client.post(f"/datasets/{SANGER_DATASET}/query", json={}, headers=headers)
    assert response.status_code == 404


@pytest.mark.parametrize(
    ("tenant", "foreign_dataset"),
    [
        (BROAD, SANGER_DATASET),
        (BROAD, RIKEN_DATASET),
        (SANGER, BROAD_DATASET),
        (SANGER, RIKEN_DATASET),
        (RIKEN, BROAD_DATASET),
        (RIKEN, SANGER_DATASET),
    ],
)
def test_idor_denied_across_every_tenant_pair(
    client: TestClient, live_settings, tenant: str, foreign_dataset: str
) -> None:
    """All six ordered pairs across the three labs."""
    headers = auth(
        user_id=f"u-{tenant}-admin",
        tenant=tenant,
        role=Role.LAB_ADMIN,
        grants=frozenset({foreign_dataset}),
        settings=live_settings,
    )
    assert (
        client.post(f"/datasets/{foreign_dataset}/query", json={}, headers=headers).status_code
        == 404
    )


def test_idor_within_own_tenant_without_grant_is_denied(
    client: TestClient, live_settings
) -> None:
    """Same lab is not sufficient; the dataset grant is enforced separately."""
    headers = auth(
        user_id="u-broad-research",
        tenant=BROAD,
        role=Role.RESEARCHER,
        grants=frozenset({BROAD_DATASET}),
        settings=live_settings,
    )
    assert (
        client.post(f"/datasets/{BROAD_DATASET_UNGRANTED}/query", json={}, headers=headers)
        .status_code
        == 404
    )


def test_cross_tenant_upload_is_denied(client: TestClient, live_settings) -> None:
    """Writing into another lab's dataset must fail as surely as reading."""
    headers = auth(
        user_id="u-broad-admin", tenant=BROAD, role=Role.LAB_ADMIN, settings=live_settings
    )
    response = client.post(
        f"/datasets/{SANGER_DATASET}/records",
        json={"records": [{"specimen_label": "INJECTED", "payload": "x"}]},
        headers=headers,
    )
    assert response.status_code == 404


def test_cross_tenant_delete_is_denied(client: TestClient, live_settings) -> None:
    headers = auth(
        user_id="u-broad-admin", tenant=BROAD, role=Role.LAB_ADMIN, settings=live_settings
    )
    assert client.delete(f"/datasets/{SANGER_DATASET}", headers=headers).status_code == 404


# --- Information leakage ----------------------------------------------------


def test_denied_and_nonexistent_are_indistinguishable(
    client: TestClient, live_settings
) -> None:
    """A 403 would confirm existence, letting an attacker enumerate holdings.

    Dataset names alone can be sensitive, so both cases must return an
    identical 404 with an identical body.
    """
    headers = auth(
        user_id="u-broad-admin", tenant=BROAD, role=Role.LAB_ADMIN, settings=live_settings
    )
    real_but_forbidden = client.post(
        f"/datasets/{SANGER_DATASET}/query", json={}, headers=headers
    )
    pure_fiction = client.post(
        "/datasets/ds-does-not-exist-at-all/query", json={}, headers=headers
    )

    assert real_but_forbidden.status_code == pure_fiction.status_code == 404
    assert real_but_forbidden.json() == pure_fiction.json()


def test_listing_excludes_other_tenants_datasets(client: TestClient, live_settings) -> None:
    headers = auth(
        user_id="u-broad-admin", tenant=BROAD, role=Role.LAB_ADMIN, settings=live_settings
    )
    body = client.get("/datasets", headers=headers).json()
    returned = {d["id"] for d in body}

    assert SANGER_DATASET not in returned
    assert RIKEN_DATASET not in returned
    assert returned, "lab-broad admin should see their own datasets"


def test_researcher_listing_excludes_ungranted_datasets(
    client: TestClient, live_settings
) -> None:
    headers = auth(
        user_id="u-broad-research",
        tenant=BROAD,
        role=Role.RESEARCHER,
        grants=frozenset({BROAD_DATASET}),
        settings=live_settings,
    )
    returned = {d["id"] for d in client.get("/datasets", headers=headers).json()}
    assert returned == {BROAD_DATASET}


# --- MANDATED: SQL injection ------------------------------------------------


SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE genomic_records; --",
    "' UNION SELECT payload_ciphertext FROM genomic_records --",
    "1' OR tenant_id='lab-sanger",
    "\\'; DELETE FROM audit_entries; --",
    "%' OR '1'='1",
    "' OR 1=1 --",
    "admin'--",
]


@pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
def test_sql_injection_in_query_filter_is_neutralised(
    client: TestClient, live_settings, payload: str
) -> None:
    """Injection attempts must be treated as literal search text.

    Queries are parameterized, so these are bound as values rather than
    parsed as SQL. A successful injection would either error or return rows
    the filter should have excluded.
    """
    headers = auth(
        user_id="u-broad-research",
        tenant=BROAD,
        role=Role.RESEARCHER,
        grants=frozenset({BROAD_DATASET}),
        settings=live_settings,
    )
    response = client.post(
        f"/datasets/{BROAD_DATASET}/query",
        json={"specimen_label": payload},
        headers=headers,
    )

    assert response.status_code == 200, response.text
    assert response.json() == [], "injection payload matched records; filter was not literal"


def test_tables_survive_injection_attempts(client: TestClient, live_settings) -> None:
    """After every payload above, the data must still be there."""
    headers = auth(
        user_id="u-broad-research",
        tenant=BROAD,
        role=Role.RESEARCHER,
        grants=frozenset({BROAD_DATASET}),
        settings=live_settings,
    )
    for payload in SQL_INJECTION_PAYLOADS:
        client.post(
            f"/datasets/{BROAD_DATASET}/query",
            json={"specimen_label": payload},
            headers=headers,
        )

    remaining = client.post(f"/datasets/{BROAD_DATASET}/query", json={}, headers=headers)
    assert remaining.status_code == 200
    assert len(remaining.json()) > 0, "records disappeared after injection attempts"


def test_like_wildcards_are_escaped(client: TestClient, live_settings) -> None:
    """A bare `%` must not widen the filter into a full scan."""
    headers = auth(
        user_id="u-broad-research",
        tenant=BROAD,
        role=Role.RESEARCHER,
        grants=frozenset({BROAD_DATASET}),
        settings=live_settings,
    )
    wildcard = client.post(
        f"/datasets/{BROAD_DATASET}/query", json={"specimen_label": "%"}, headers=headers
    )
    everything = client.post(f"/datasets/{BROAD_DATASET}/query", json={}, headers=headers)

    assert wildcard.json() == [], "unescaped % returned rows"
    assert len(everything.json()) > 0


# --- Role enforcement over HTTP ---------------------------------------------


def test_read_only_cannot_upload(client: TestClient, live_settings) -> None:
    headers = auth(
        user_id="u-broad-readonly",
        tenant=BROAD,
        role=Role.READ_ONLY,
        grants=frozenset({BROAD_DATASET}),
        settings=live_settings,
    )
    response = client.post(
        f"/datasets/{BROAD_DATASET}/records",
        json={"records": [{"specimen_label": "X", "payload": "y"}]},
        headers=headers,
    )
    assert response.status_code == 404


def test_researcher_cannot_delete(client: TestClient, live_settings) -> None:
    headers = auth(
        user_id="u-broad-research",
        tenant=BROAD,
        role=Role.RESEARCHER,
        grants=frozenset({BROAD_DATASET}),
        settings=live_settings,
    )
    assert client.delete(f"/datasets/{BROAD_DATASET}", headers=headers).status_code == 404


def test_researcher_cannot_read_audit_log(client: TestClient, live_settings) -> None:
    headers = auth(
        user_id="u-broad-research",
        tenant=BROAD,
        role=Role.RESEARCHER,
        grants=frozenset({BROAD_DATASET}),
        settings=live_settings,
    )
    assert client.get("/audit", headers=headers).status_code == 404


def test_auditor_can_read_own_tenant_audit_log(client: TestClient, live_settings) -> None:
    headers = auth(
        user_id="u-broad-auditor", tenant=BROAD, role=Role.AUDITOR, settings=live_settings
    )
    response = client.get("/audit", headers=headers)
    assert response.status_code == 200
    assert all(e["actor_id"] for e in response.json())


def test_auditor_cannot_read_dataset_contents(client: TestClient, live_settings) -> None:
    """Separation of duty: auditors review access, not genomic data."""
    headers = auth(
        user_id="u-broad-auditor",
        tenant=BROAD,
        role=Role.AUDITOR,
        grants=frozenset({BROAD_DATASET}),
        settings=live_settings,
    )
    assert (
        client.post(f"/datasets/{BROAD_DATASET}/query", json={}, headers=headers).status_code
        == 404
    )


# --- PHI record-level filtering ---------------------------------------------


def test_uncleared_researcher_receives_only_non_phi_records(
    client: TestClient, live_settings
) -> None:
    headers = auth(
        user_id="u-broad-research",
        tenant=BROAD,
        role=Role.RESEARCHER,
        grants=frozenset({BROAD_DATASET}),
        phi_cleared=False,
        settings=live_settings,
    )
    body = client.post(f"/datasets/{BROAD_DATASET}/query", json={}, headers=headers).json()

    assert body, "expected some non-PHI records"
    assert all(r["contains_phi"] is False for r in body)


def test_cleared_researcher_receives_phi_records(client: TestClient, live_settings) -> None:
    headers = auth(
        user_id="u-broad-research",
        tenant=BROAD,
        role=Role.RESEARCHER,
        grants=frozenset({BROAD_DATASET}),
        phi_cleared=True,
        settings=live_settings,
    )
    body = client.post(f"/datasets/{BROAD_DATASET}/query", json={}, headers=headers).json()
    assert any(r["contains_phi"] is True for r in body)


def test_phi_filter_cannot_be_bypassed_by_requesting_phi_explicitly(
    client: TestClient, live_settings
) -> None:
    """Asking for PHI directly must not override the clearance check."""
    headers = auth(
        user_id="u-broad-research",
        tenant=BROAD,
        role=Role.RESEARCHER,
        grants=frozenset({BROAD_DATASET}),
        phi_cleared=False,
        settings=live_settings,
    )
    body = client.post(
        f"/datasets/{BROAD_DATASET}/query", json={"contains_phi": True}, headers=headers
    ).json()
    assert body == []


# --- Input validation -------------------------------------------------------


@pytest.mark.parametrize(
    "bad_body",
    [
        {"records": []},
        {"records": [{"specimen_label": "", "payload": "x"}]},
        {"records": [{"specimen_label": "X"}]},
        {"records": [{"specimen_label": "X", "payload": "y", "tenant_id": SANGER}]},
        {"unexpected": "field"},
    ],
)
def test_invalid_upload_bodies_are_rejected(
    client: TestClient, live_settings, bad_body: dict
) -> None:
    """`extra="forbid"` also blocks a client smuggling a tenant_id field."""
    headers = auth(
        user_id="u-broad-admin", tenant=BROAD, role=Role.LAB_ADMIN, settings=live_settings
    )
    response = client.post(
        f"/datasets/{BROAD_DATASET}/records", json=bad_body, headers=headers
    )
    assert response.status_code == 422


def test_query_limit_is_bounded(client: TestClient, live_settings) -> None:
    """An unbounded limit is a denial-of-service and exfiltration vector."""
    headers = auth(
        user_id="u-broad-research",
        tenant=BROAD,
        role=Role.RESEARCHER,
        grants=frozenset({BROAD_DATASET}),
        settings=live_settings,
    )
    assert (
        client.post(
            f"/datasets/{BROAD_DATASET}/query", json={"limit": 100_000}, headers=headers
        ).status_code
        == 422
    )
