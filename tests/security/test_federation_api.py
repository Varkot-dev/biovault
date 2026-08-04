"""Federated cohort discovery over HTTP.

The capability under test: a researcher at one lab learns an aggregate spanning
all three labs, while record-level cross-tenant access stays impossible.

Those two properties are in tension, and the tension is the point. Most of
these tests exist to confirm the federation path did not become a side channel
around the isolation the rest of the system enforces.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from biovault.auth.tokens import issue_access_token
from biovault.authz.policy import Role

pytestmark = [pytest.mark.security, pytest.mark.integration]

BROAD = "lab-broad"
SANGER = "lab-sanger"

# A gene present in every lab's synthetic data, so a query on it exercises a
# genuine multi-site cohort rather than an accidentally empty one.
GENE = "BRCA1"


@pytest.fixture
def client(live_settings) -> TestClient:
    from biovault.api.main import app

    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def _fresh_budget(owner_session):
    """Give each test a clean budget for the tenants it queries.

    The ledger is append-only for the application role, so this runs as the
    schema owner — the only role permitted to delete, which
    `test_deleting_budget_entries_fails_at_runtime` asserts.

    Committing on a separate connection matters: the API under test opens its
    own sessions, so an uncommitted delete would be invisible to it and every
    test after the first would see an exhausted budget. That is exactly the
    failure this fixture initially had.
    """
    from sqlalchemy import create_engine

    from biovault.config import get_settings

    engine = create_engine(get_settings().database_url(as_owner=True), future=True)
    with engine.begin() as conn:
        # Both ledgers. Outbound bounds what a lab may SPEND; inbound bounds
        # what may be EXTRACTED FROM it. Clearing only the first leaves every
        # site refusing on its own ceiling after a few tests, which surfaces as
        # every query returning null rather than as an obvious budget error.
        conn.execute(
            text(
                "DELETE FROM privacy_budget_entries WHERE tenant_id IN "
                "('lab-broad', 'lab-sanger', 'lab-riken')"
            )
        )
        conn.execute(
            text(
                "DELETE FROM inbound_epsilon_entries WHERE tenant_id IN "
                "('lab-broad', 'lab-sanger', 'lab-riken')"
            )
        )
    engine.dispose()
    yield


def auth(settings, *, tenant: str = BROAD, role: Role = Role.RESEARCHER,
         user_id: str = "u-broad-research", grants=frozenset()) -> dict[str, str]:
    token = issue_access_token(
        subject=user_id,
        tenant_id=tenant,
        role=role,
        dataset_grants=grants,
        phi_cleared=False,
        secret=settings.jwt_secret.get_secret_value(),
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        ttl_seconds=900,
    )
    return {"Authorization": f"Bearer {token}"}


# --- The capability ---------------------------------------------------------


def test_researcher_receives_an_aggregate_spanning_all_labs(
    client, live_settings
) -> None:
    """The point of the whole feature.

    A Broad researcher learns a count covering Broad, Sanger, and RIKEN — a
    question that is otherwise unanswerable without shipping records between
    institutions.
    """
    response = client.post(
        "/federation/cohort-count",
        json={"gene": GENE, "epsilon": 0.1},
        headers=auth(live_settings),
    )
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["sites_queried"] == 3
    assert body["total"] is not None
    # One Laplace release per site, so the cost is epsilon * sites. Charging
    # epsilon once would undercount real privacy loss threefold.
    assert body["epsilon_spent"] == pytest.approx(0.3)
    assert body["interval"] is not None, "a count must never ship without its interval"


def test_response_reports_which_sites_contributed(client, live_settings) -> None:
    """Participation is disclosed; the underlying counts are not."""
    body = client.post(
        "/federation/cohort-count",
        json={"gene": GENE, "epsilon": 0.1},
        headers=auth(live_settings),
    ).json()

    tenants = {c["tenant_id"] for c in body["contributions"]}
    assert tenants == {BROAD, SANGER, "lab-riken"}
    for contribution in body["contributions"]:
        assert set(contribution) == {"tenant_id", "suppressed"}, (
            "a per-site count leaked into the response"
        )


def test_repeated_identical_queries_return_different_answers(
    client, live_settings
) -> None:
    """Deterministic answers would be exact counts, not private ones."""
    answers = []
    # Budget permits 1.0 / (0.1 * 3) = 3 federated queries.
    for _ in range(3):
        body = client.post(
            "/federation/cohort-count",
            json={"gene": GENE, "epsilon": 0.1},
            headers=auth(live_settings),
        ).json()
        if body["total"] is not None:
            answers.append(body["total"])

    assert len(set(answers)) > 1, "federated answers are deterministic"


# --- Federation must not become a side channel ------------------------------


def test_response_contains_no_record_level_data(client, live_settings) -> None:
    """The critical containment property.

    A federated response must carry no specimen labels, record ids, dataset
    ids, or payloads. Serialising the whole body and searching for known
    identifiers catches a leak through any field, including ones added later.
    """
    raw = client.post(
        "/federation/cohort-count",
        json={"gene": GENE, "epsilon": 0.1},
        headers=auth(live_settings),
    ).text

    for forbidden in (
        "SPEC-",           # specimen labels
        "ds-sanger",       # another lab's dataset id
        "ds-broad",
        "c.0000",          # variant coordinates -- only ever in ciphertext
        "GT=",             # genotype -- the identifying part of a call
        "DP=",             # read depth
        "TP53",            # a gene the caller did not ask about
        "payload",
        "specimen",
        "gene_symbol",
    ):
        assert forbidden not in raw, f"federated response leaked {forbidden!r}"


def test_response_does_not_echo_the_queried_gene(client, live_settings) -> None:
    """The queried gene is the caller's own input, but echoing it is still wrong.

    A response that repeats the predicate makes it trivially easy for a proxy,
    log sink, or client-side cache to accumulate a picture of which loci a lab
    is investigating. Research direction is itself sensitive, which is the same
    reason `/federation/budget` does not report other tenants' spending.
    """
    raw = client.post(
        "/federation/cohort-count",
        json={"gene": GENE, "epsilon": 0.1},
        headers=auth(live_settings),
    ).text

    assert GENE not in raw


def test_federation_does_not_grant_record_access(client, live_settings) -> None:
    """Using federation must not change what the caller can read directly."""
    headers = auth(live_settings)

    client.post(
        "/federation/cohort-count",
        json={"gene": GENE, "epsilon": 0.1},
        headers=headers,
    )

    still_denied = client.post(
        "/datasets/ds-sanger-onco-1/query", json={}, headers=headers
    )
    assert still_denied.status_code == 404


def test_exact_per_site_counts_are_never_returned(client, live_settings) -> None:
    """Per-site exact counts would identify which lab holds which cohort.

    Only the combined total is released, and only when at least two sites
    contribute.
    """
    body = client.post(
        "/federation/cohort-count",
        json={"gene": GENE, "epsilon": 0.1},
        headers=auth(live_settings),
    ).json()

    for contribution in body["contributions"]:
        assert "value" not in contribution
        assert "count" not in contribution


# --- Authorization ----------------------------------------------------------


def test_unauthenticated_federation_is_rejected(client) -> None:
    response = client.post(
        "/federation/cohort-count", json={"gene": GENE, "epsilon": 0.1}
    )
    assert response.status_code == 401


def test_auditor_cannot_run_federated_queries(client, live_settings) -> None:
    """An auditor reviews access; they do not query genomic aggregates."""
    response = client.post(
        "/federation/cohort-count",
        json={"gene": GENE, "epsilon": 0.1},
        headers=auth(live_settings, role=Role.AUDITOR, user_id="u-broad-auditor"),
    )
    assert response.status_code == 404


def test_budget_is_visible_to_its_owner(client, live_settings) -> None:
    response = client.get("/federation/budget", headers=auth(live_settings))
    assert response.status_code == 200
    body = response.json()
    assert body["total"] > 0
    assert 0 <= body["remaining"] <= body["total"]


def test_budget_endpoint_reports_only_the_callers_tenant(client, live_settings) -> None:
    """Query volume reveals research direction, so budgets are not shared."""
    body = client.get("/federation/budget", headers=auth(live_settings)).json()
    assert set(body) == {"total", "remaining", "spent"}


# --- Budget enforcement over HTTP -------------------------------------------


def test_budget_exhaustion_returns_429(client, live_settings) -> None:
    """A quota condition that resolves with time, not an authorization failure.

    429 rather than 403 tells the client to wait rather than to seek different
    permissions.
    """
    headers = auth(live_settings)
    statuses = [
        client.post(
            "/federation/cohort-count",
            json={"gene": GENE, "epsilon": 1.0},
            headers=headers,
        ).status_code
        for _ in range(3)
    ]
    assert 429 in statuses, f"budget was never exhausted: {statuses}"


def test_spending_reduces_reported_remaining_budget(client, live_settings) -> None:
    headers = auth(live_settings)
    before = client.get("/federation/budget", headers=headers).json()["remaining"]

    client.post(
        "/federation/cohort-count",
        json={"gene": GENE, "epsilon": 0.1},
        headers=headers,
    )

    after = client.get("/federation/budget", headers=headers).json()["remaining"]
    # epsilon * 3 sites
    assert before - after == pytest.approx(0.3)


def test_budgets_are_independent_across_tenants(client, live_settings) -> None:
    """One lab exhausting its budget must not deny service to another."""
    broad = auth(live_settings, tenant=BROAD)
    sanger = auth(live_settings, tenant=SANGER, user_id="u-sanger-research")

    for _ in range(3):
        client.post(
            "/federation/cohort-count",
            json={"gene": GENE, "epsilon": 1.0},
            headers=broad,
        )

    response = client.post(
        "/federation/cohort-count",
        json={"gene": GENE, "epsilon": 0.1},
        headers=sanger,
    )
    assert response.status_code == 200, "one tenant's spending blocked another"


# --- Input validation -------------------------------------------------------


@pytest.mark.parametrize("epsilon", [0.0, -1.0, 5.0, 1000.0])
def test_out_of_range_epsilon_is_rejected(client, live_settings, epsilon: float) -> None:
    """A caller must not be able to request negligible noise."""
    response = client.post(
        "/federation/cohort-count",
        json={"gene": GENE, "epsilon": epsilon},
        headers=auth(live_settings),
    )
    assert response.status_code == 422


@pytest.mark.parametrize("gene", ["", "x", "a" * 41])
def test_malformed_gene_is_rejected(client, live_settings, gene: str) -> None:
    """No real gene symbol is empty, one character, or 41 characters long.

    Bounding the predicate at the boundary keeps obviously-malformed input from
    reaching the database at all, and costs the caller no budget when it is
    rejected.
    """
    response = client.post(
        "/federation/cohort-count",
        json={"gene": gene, "epsilon": 0.1},
        headers=auth(live_settings),
    )
    assert response.status_code == 422


def test_an_unknown_gene_costs_budget_and_reveals_nothing(
    client, live_settings
) -> None:
    """A gene no lab holds must behave like any other query, not like an error.

    Exact matching means a caller can name a gene that matches zero records.
    That must still charge budget and still return a suppressed answer: a
    distinguishable "no such gene" response would let an attacker enumerate
    which loci the consortium sequences for free, and free queries are exactly
    what the budget exists to prevent.
    """
    # Take the comparison query FIRST so the budget delta below measures only
    # the unknown-gene query. Measuring across both would report 0.6 and the
    # assertion would be checking arithmetic rather than the property.
    known = client.post(
        "/federation/cohort-count",
        json={"gene": "BRCA1", "epsilon": 0.1},
        headers=auth(live_settings),
    )

    before = client.get("/federation/budget", headers=auth(live_settings)).json()[
        "remaining"
    ]
    response = client.post(
        "/federation/cohort-count",
        json={"gene": "ZZZZ9", "epsilon": 0.1},
        headers=auth(live_settings),
    )
    assert response.status_code == 200, response.text

    # Budget is charged whether or not the gene exists. Free probes would let
    # an attacker enumerate which loci the consortium sequences at no cost,
    # and unmetered queries are precisely what the budget exists to prevent.
    after = client.get("/federation/budget", headers=auth(live_settings)).json()[
        "remaining"
    ]
    assert before - after == pytest.approx(0.3), "an unknown gene was not charged"

    # The response must not distinguish "no such gene" from a real one.
    # Asserting `suppressed is True` here would be wrong: suppression is
    # randomized by design, so a zero-count query sometimes clears the noisy
    # threshold and reports a small value -- the mechanism working, not a leak.
    # Shape equality is the property that actually matters.
    assert known.status_code == response.status_code
    assert set(known.json()) == set(response.json()), (
        "an unknown gene produces a distinguishable response shape"
    )

    after = client.get("/federation/budget", headers=auth(live_settings)).json()[
        "remaining"
    ]
    assert before - after == pytest.approx(0.3), "an empty cohort was answered for free"


def test_gene_filter_matches_exactly_not_as_a_substring(client, live_settings) -> None:
    """Exact equality, so a partial gene name selects nothing.

    Under the old substring match, `BRCA` would have matched `BRCA1` and a
    caller could have shrunk a predicate character by character to isolate a
    cohort. With exact matching, a prefix of a real gene is simply not a gene.
    """
    partial = client.post(
        "/federation/cohort-count",
        json={"gene": "BRCA", "epsilon": 0.1},
        headers=auth(live_settings),
    ).json()
    exact = client.post(
        "/federation/cohort-count",
        json={"gene": "BRCA1", "epsilon": 0.1},
        headers=auth(live_settings),
    ).json()

    # The property is that the partial name selects no records -- not that the
    # response is suppressed. Suppression is randomized by design (the flag is
    # itself a DP release), so a zero-count query can occasionally survive the
    # threshold and report a small noisy value. Comparing against the exact
    # match is the assertion that survives that randomness: a prefix of a real
    # gene must not behave like the gene.
    if not partial["suppressed"] and not exact["suppressed"]:
        assert partial["total"] < exact["total"], (
            "a partial gene name matched as many records as the real gene; "
            "the filter is behaving like a substring match"
        )


def test_sql_injection_in_the_gene_filter_is_neutralised(
    client, live_settings
) -> None:
    """The federated path uses the same parameterized queries as the rest."""
    response = client.post(
        "/federation/cohort-count",
        json={"gene": "'; DROP TABLE genomic_records; --", "epsilon": 0.1},
        headers=auth(live_settings),
    )
    assert response.status_code == 200

    survived = client.post(
        "/federation/cohort-count",
        json={"gene": GENE, "epsilon": 0.1},
        headers=auth(live_settings),
    )
    assert survived.status_code == 200
    assert survived.json()["sites_queried"] == 3


def test_extra_request_fields_are_rejected(client, live_settings) -> None:
    """`extra="forbid"` blocks smuggling a tenant override into the query."""
    response = client.post(
        "/federation/cohort-count",
        json={"gene": GENE, "epsilon": 0.1, "tenant_id": SANGER},
        headers=auth(live_settings),
    )
    assert response.status_code == 422
