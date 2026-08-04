"""End-to-end OAuth 2.0 authorization-code flow with PKCE.

The happy path here is worth as much as the negatives: it proves PKCE is a
*working flow* rather than a tested primitive with no callers. The negatives
then attack each binding the code carries — verifier, client, redirect URI,
expiry, single-use.
"""

from __future__ import annotations

import secrets

import pytest
from fastapi.testclient import TestClient

from biovault.auth.pkce import derive_challenge

pytestmark = [pytest.mark.security, pytest.mark.integration]

BROAD_RESEARCHER = "u-broad-research"
SANGER_RESEARCHER = "u-sanger-research"


@pytest.fixture
def client(live_settings) -> TestClient:
    from biovault.api.main import app

    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def verifier() -> str:
    return secrets.token_urlsafe(64)[:64]


def authorize(client: TestClient, settings, verifier: str, user_id: str = BROAD_RESEARCHER):
    return client.post(
        "/auth/authorize",
        json={
            "response_type": "code",
            "client_id": settings.oauth_client_id,
            "redirect_uri": settings.oauth_redirect_uri,
            "code_challenge": derive_challenge(verifier),
            "code_challenge_method": "S256",
            "user_id": user_id,
        },
    )


def redeem(client: TestClient, settings, code: str, verifier: str, **overrides):
    body = {
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": verifier,
        "client_id": settings.oauth_client_id,
        "redirect_uri": settings.oauth_redirect_uri,
    }
    body.update(overrides)
    return client.post("/auth/token", json=body)


# --- Happy path -------------------------------------------------------------


def test_full_flow_yields_a_usable_access_token(client, live_settings, verifier) -> None:
    """authorize → token → use the token on a protected endpoint.

    This is the test that makes PKCE a flow rather than a primitive.
    """
    auth_response = authorize(client, live_settings, verifier)
    assert auth_response.status_code == 200, auth_response.text
    code = auth_response.json()["code"]

    token_response = redeem(client, live_settings, code, verifier)
    assert token_response.status_code == 200, token_response.text
    body = token_response.json()

    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == live_settings.access_token_ttl_seconds
    assert body["access_token"] and body["refresh_token"]

    protected = client.get(
        "/datasets", headers={"Authorization": f"Bearer {body['access_token']}"}
    )
    assert protected.status_code == 200


def test_issued_token_carries_grants_from_the_database(
    client, live_settings, verifier
) -> None:
    """Grants are read server-side at issue time, never taken from the client.

    The seeded researcher holds exactly one dataset grant, so the token must
    scope them to that dataset and nothing else.
    """
    code = authorize(client, live_settings, verifier).json()["code"]
    access = redeem(client, live_settings, code, verifier).json()["access_token"]

    listed = client.get("/datasets", headers={"Authorization": f"Bearer {access}"})
    assert {d["id"] for d in listed.json()} == {"ds-broad-cohort-1"}


def test_token_scopes_the_user_to_their_own_tenant(client, live_settings, verifier) -> None:
    """A Sanger user's token must not reach Broad data."""
    code = authorize(client, live_settings, verifier, user_id=SANGER_RESEARCHER).json()["code"]
    access = redeem(client, live_settings, code, verifier).json()["access_token"]

    denied = client.post(
        "/datasets/ds-broad-cohort-1/query",
        json={},
        headers={"Authorization": f"Bearer {access}"},
    )
    assert denied.status_code == 404


# --- PKCE binding -----------------------------------------------------------


def test_wrong_verifier_is_rejected(client, live_settings, verifier) -> None:
    """The central PKCE guarantee: a stolen code is useless without the verifier."""
    code = authorize(client, live_settings, verifier).json()["code"]
    stolen_attempt = redeem(client, live_settings, code, secrets.token_urlsafe(64)[:64])
    assert stolen_attempt.status_code == 400


def test_missing_verifier_is_rejected(client, live_settings, verifier) -> None:
    code = authorize(client, live_settings, verifier).json()["code"]
    response = client.post(
        "/auth/token",
        json={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": live_settings.oauth_client_id,
            "redirect_uri": live_settings.oauth_redirect_uri,
        },
    )
    assert response.status_code == 422


def test_challenge_sent_as_the_verifier_is_rejected(client, live_settings, verifier) -> None:
    """A `plain`-style downgrade attempt must fail."""
    challenge = derive_challenge(verifier)
    code = authorize(client, live_settings, verifier).json()["code"]
    assert redeem(client, live_settings, code, challenge).status_code == 400


# --- Single use -------------------------------------------------------------


def test_authorization_code_is_single_use(client, live_settings, verifier) -> None:
    """Replay must fail even with the correct verifier."""
    code = authorize(client, live_settings, verifier).json()["code"]

    assert redeem(client, live_settings, code, verifier).status_code == 200
    assert redeem(client, live_settings, code, verifier).status_code == 400


def test_unknown_code_is_rejected(client, live_settings, verifier) -> None:
    assert redeem(client, live_settings, "never-issued-code", verifier).status_code == 400


# --- Client and redirect binding --------------------------------------------


def test_wrong_client_id_at_redemption_is_rejected(client, live_settings, verifier) -> None:
    code = authorize(client, live_settings, verifier).json()["code"]
    response = redeem(client, live_settings, code, verifier, client_id="different-client")
    assert response.status_code == 400


def test_wrong_redirect_uri_at_redemption_is_rejected(
    client, live_settings, verifier
) -> None:
    """RFC 6749 4.1.3 requires the redirect URI to match the authorization request.

    Without this, an attacker who can register a redirect could have the code
    delivered to an address they control.
    """
    code = authorize(client, live_settings, verifier).json()["code"]
    response = redeem(client, live_settings, code, verifier,
                      redirect_uri="https://evil.example/callback")
    assert response.status_code == 400


def test_unregistered_client_cannot_obtain_a_code(client, live_settings, verifier) -> None:
    response = client.post(
        "/auth/authorize",
        json={
            "response_type": "code",
            "client_id": "unregistered-client",
            "redirect_uri": live_settings.oauth_redirect_uri,
            "code_challenge": derive_challenge(verifier),
            "code_challenge_method": "S256",
            "user_id": BROAD_RESEARCHER,
        },
    )
    assert response.status_code == 400


def test_unregistered_redirect_uri_cannot_obtain_a_code(
    client, live_settings, verifier
) -> None:
    response = client.post(
        "/auth/authorize",
        json={
            "response_type": "code",
            "client_id": live_settings.oauth_client_id,
            "redirect_uri": "https://evil.example/callback",
            "code_challenge": derive_challenge(verifier),
            "code_challenge_method": "S256",
            "user_id": BROAD_RESEARCHER,
        },
    )
    assert response.status_code == 400


def test_unknown_user_returns_the_same_error_as_a_bad_client(
    client, live_settings, verifier
) -> None:
    """Otherwise the endpoint becomes an account-enumeration oracle."""
    unknown = authorize(client, live_settings, verifier, user_id="u-does-not-exist")
    bad_client = client.post(
        "/auth/authorize",
        json={
            "response_type": "code",
            "client_id": "unregistered-client",
            "redirect_uri": live_settings.oauth_redirect_uri,
            "code_challenge": derive_challenge(verifier),
            "code_challenge_method": "S256",
            "user_id": BROAD_RESEARCHER,
        },
    )
    assert unknown.status_code == bad_client.status_code == 400
    assert unknown.json() == bad_client.json()


# --- Protocol validation ----------------------------------------------------


@pytest.mark.parametrize("method", ["plain", "S512", "sha256", ""])
def test_non_s256_challenge_methods_are_refused(
    client, live_settings, verifier, method: str
) -> None:
    response = client.post(
        "/auth/authorize",
        json={
            "response_type": "code",
            "client_id": live_settings.oauth_client_id,
            "redirect_uri": live_settings.oauth_redirect_uri,
            "code_challenge": derive_challenge(verifier),
            "code_challenge_method": method,
            "user_id": BROAD_RESEARCHER,
        },
    )
    assert response.status_code == 422


@pytest.mark.parametrize("grant", ["password", "client_credentials", "implicit", ""])
def test_unsupported_grant_types_are_refused(
    client, live_settings, verifier, grant: str
) -> None:
    """Only authorization_code is supported; `password` in particular is
    deprecated precisely because it hands credentials to the client."""
    code = authorize(client, live_settings, verifier).json()["code"]
    assert redeem(client, live_settings, code, verifier, grant_type=grant).status_code == 422


def test_short_challenge_is_refused(client, live_settings) -> None:
    """A short challenge implies a brute-forceable verifier."""
    response = client.post(
        "/auth/authorize",
        json={
            "response_type": "code",
            "client_id": live_settings.oauth_client_id,
            "redirect_uri": live_settings.oauth_redirect_uri,
            "code_challenge": "tooshort",
            "code_challenge_method": "S256",
            "user_id": BROAD_RESEARCHER,
        },
    )
    assert response.status_code == 422


def test_error_bodies_do_not_distinguish_failure_causes(
    client, live_settings, verifier
) -> None:
    """Uniform errors prevent probing which part of a guess was correct."""
    code_a = authorize(client, live_settings, verifier).json()["code"]
    code_b = authorize(client, live_settings, verifier).json()["code"]
    code_c = authorize(client, live_settings, verifier).json()["code"]

    bodies = {
        redeem(client, live_settings, code_a, secrets.token_urlsafe(64)[:64]).json()["detail"],
        redeem(client, live_settings, code_b, verifier, client_id="other").json()["detail"],
        redeem(client, live_settings, code_c, verifier,
               redirect_uri="https://evil.example/cb").json()["detail"],
        redeem(client, live_settings, "unknown-code", verifier).json()["detail"],
    }
    assert len(bodies) == 1, f"error bodies leak the cause: {bodies}"
