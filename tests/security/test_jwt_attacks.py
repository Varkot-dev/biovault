"""Negative-case tests against JWT verification.

Each test here corresponds to a real, exploited attack against JWT
implementations. They are written as attacks — construct a hostile token, then
assert it is rejected — rather than as assertions about internal state.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from biovault.auth.tokens import (
    ALLOWED_ALGORITHMS,
    TokenError,
    issue_access_token,
    verify_access_token,
)
from biovault.authz.policy import Role

pytestmark = pytest.mark.security

SECRET = "test-secret-that-is-definitely-long-enough-for-hs256"
OTHER_SECRET = "a-completely-different-secret-of-sufficient-length!!"
ISSUER = "https://biovault.local"
AUDIENCE = "biovault-api"


def make_token(**overrides) -> str:
    params = {
        "subject": "u-1",
        "tenant_id": "lab-broad",
        "role": Role.RESEARCHER,
        "dataset_grants": frozenset({"ds-1"}),
        "phi_cleared": False,
        "secret": SECRET,
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "ttl_seconds": 900,
    }
    params.update(overrides)
    return issue_access_token(**params)


def verify(token: str, **overrides):
    params = {"secret": SECRET, "issuer": ISSUER, "audience": AUDIENCE}
    params.update(overrides)
    return verify_access_token(token, **params)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


# --- Baseline: the happy path must work, or negatives prove nothing ---------


def test_valid_token_verifies_and_round_trips_claims() -> None:
    token = make_token()
    claims = verify(token)
    assert claims.subject == "u-1"
    assert claims.tenant_id == "lab-broad"
    assert claims.role is Role.RESEARCHER
    assert claims.dataset_grants == frozenset({"ds-1"})


# --- MANDATED: alg:none attack ----------------------------------------------


def test_alg_none_token_is_rejected() -> None:
    """The classic JWT bypass: declare no algorithm and omit the signature.

    Libraries that read `alg` from the token accept this as valid, letting an
    attacker mint arbitrary claims. Defence is passing an explicit algorithm
    allowlist to decode, never trusting the header.
    """
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64url(
        json.dumps(
            {
                "sub": "attacker",
                "iss": ISSUER,
                "aud": AUDIENCE,
                "iat": int(datetime.now(UTC).timestamp()),
                "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
                "typ": "access",
                "tenant": "lab-broad",
                "role": "lab_admin",
                "phi_cleared": True,
                "grants": ["ds-1"],
            }
        ).encode()
    )
    forged = f"{header}.{payload}."

    with pytest.raises(TokenError):
        verify(forged)


def test_alg_none_with_uppercase_variants_is_rejected() -> None:
    """Case-variant bypasses (`None`, `NONE`, `nOnE`) must also fail."""
    for variant in ("None", "NONE", "nOnE", "nonE"):
        header = _b64url(json.dumps({"alg": variant, "typ": "JWT"}).encode())
        payload = _b64url(
            json.dumps(
                {
                    "sub": "attacker",
                    "iss": ISSUER,
                    "aud": AUDIENCE,
                    "iat": int(datetime.now(UTC).timestamp()),
                    "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
                    "typ": "access",
                    "tenant": "lab-broad",
                    "role": "lab_admin",
                    "grants": [],
                }
            ).encode()
        )
        with pytest.raises(TokenError):
            verify(f"{header}.{payload}.")


def test_only_hs256_is_accepted() -> None:
    """Guard the allowlist itself against being widened by accident."""
    assert ALLOWED_ALGORITHMS == ("HS256",)


# --- MANDATED: tampered signature -------------------------------------------


def test_tampered_signature_is_rejected() -> None:
    token = make_token()
    header, payload, signature = token.split(".")
    flipped = "A" if signature[0] != "A" else "B"
    with pytest.raises(TokenError):
        verify(f"{header}.{payload}.{flipped}{signature[1:]}")


def test_tampered_payload_is_rejected() -> None:
    """Editing claims invalidates the signature over them."""
    token = make_token()
    header, _, signature = token.split(".")
    hostile = _b64url(
        json.dumps(
            {
                "sub": "u-1",
                "iss": ISSUER,
                "aud": AUDIENCE,
                "iat": int(datetime.now(UTC).timestamp()),
                "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
                "typ": "access",
                "tenant": "lab-broad",
                "role": "lab_admin",
                "grants": ["ds-1"],
            }
        ).encode()
    )
    with pytest.raises(TokenError):
        verify(f"{header}.{hostile}.{signature}")


def test_token_signed_with_a_different_secret_is_rejected() -> None:
    token = make_token(secret=OTHER_SECRET)
    with pytest.raises(TokenError):
        verify(token)


def test_stripped_signature_is_rejected() -> None:
    token = make_token()
    header, payload, _ = token.split(".")
    with pytest.raises(TokenError):
        verify(f"{header}.{payload}.")


# --- MANDATED: privilege escalation via role manipulation -------------------


def test_role_escalation_in_payload_is_rejected() -> None:
    """Rewriting `role` to lab_admin invalidates the signature.

    Role comes from the signed token, never from the request, which is what
    makes this attack a signature failure rather than an authorization bug.
    """
    token = make_token(role=Role.READ_ONLY)
    header, payload, signature = token.split(".")

    decoded = json.loads(base64.urlsafe_b64decode(payload + "=="))
    decoded["role"] = "lab_admin"
    escalated = _b64url(json.dumps(decoded).encode())

    with pytest.raises(TokenError):
        verify(f"{header}.{escalated}.{signature}")


def test_tenant_swap_in_payload_is_rejected() -> None:
    """Rewriting `tenant` to another lab must fail signature verification."""
    token = make_token(tenant_id="lab-broad")
    header, payload, signature = token.split(".")

    decoded = json.loads(base64.urlsafe_b64decode(payload + "=="))
    decoded["tenant"] = "lab-sanger"
    swapped = _b64url(json.dumps(decoded).encode())

    with pytest.raises(TokenError):
        verify(f"{header}.{swapped}.{signature}")


def test_grant_injection_in_payload_is_rejected() -> None:
    """Adding dataset grants must fail signature verification."""
    token = make_token(dataset_grants=frozenset({"ds-1"}))
    header, payload, signature = token.split(".")

    decoded = json.loads(base64.urlsafe_b64decode(payload + "=="))
    decoded["grants"] = ["ds-1", "ds-broad-cohort-2", "ds-sanger-onco-1"]
    injected = _b64url(json.dumps(decoded).encode())

    with pytest.raises(TokenError):
        verify(f"{header}.{injected}.{signature}")


def test_unknown_role_value_is_rejected() -> None:
    """A validly signed token carrying a role outside the enum must not pass."""
    payload = {
        "sub": "u-1",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(hours=1),
        "typ": "access",
        "tenant": "lab-broad",
        "role": "superuser",
        "grants": [],
    }
    token = jwt.encode(payload, SECRET, algorithm="HS256")
    with pytest.raises(TokenError):
        verify(token)


# --- MANDATED: expired tokens -----------------------------------------------


def test_expired_token_is_rejected() -> None:
    past = datetime.now(UTC) - timedelta(hours=2)
    token = make_token(ttl_seconds=60, now=past)
    with pytest.raises(TokenError):
        verify(token)


def test_token_expiring_one_second_ago_is_rejected() -> None:
    """No leeway: a grace period extends a stolen token's useful life."""
    token = make_token(ttl_seconds=1, now=datetime.now(UTC) - timedelta(seconds=2))
    with pytest.raises(TokenError):
        verify(token)


def test_token_valid_just_before_expiry_is_accepted() -> None:
    """Confirms expiry rejection is about time, not blanket failure."""
    token = make_token(ttl_seconds=3600)
    assert verify(token).subject == "u-1"


# --- Audience and issuer ----------------------------------------------------


def test_token_for_a_different_audience_is_rejected() -> None:
    """Prevents a token minted for another service being replayed here."""
    token = make_token(audience="some-other-service")
    with pytest.raises(TokenError):
        verify(token)


def test_token_from_a_different_issuer_is_rejected() -> None:
    token = make_token(issuer="https://evil.example")
    with pytest.raises(TokenError):
        verify(token)


# --- Structural / malformed input -------------------------------------------


@pytest.mark.parametrize(
    "garbage",
    ["", "not-a-token", "a.b", "a.b.c.d", "...", "Bearer abc", "null", "{}"],
)
def test_malformed_tokens_are_rejected(garbage: str) -> None:
    with pytest.raises(TokenError):
        verify(garbage)


def test_token_missing_required_claims_is_rejected() -> None:
    """A signed token lacking `tenant` must fail rather than default."""
    payload = {
        "sub": "u-1",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(hours=1),
        "typ": "access",
        "role": "researcher",
        "grants": [],
    }
    token = jwt.encode(payload, SECRET, algorithm="HS256")
    with pytest.raises(TokenError):
        verify(token)


def test_refresh_token_cannot_be_used_as_an_access_token() -> None:
    """Type confusion: refresh tokens live far longer than access tokens."""
    payload = {
        "sub": "u-1",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(days=7),
        "typ": "refresh",
        "tenant": "lab-broad",
        "role": "lab_admin",
        "grants": [],
    }
    token = jwt.encode(payload, SECRET, algorithm="HS256")
    with pytest.raises(TokenError):
        verify(token)


def test_error_message_does_not_reveal_which_check_failed() -> None:
    """Distinguishing expiry from bad signature hands an attacker an oracle."""
    expired = make_token(ttl_seconds=1, now=datetime.now(UTC) - timedelta(hours=1))
    wrong_key = make_token(secret=OTHER_SECRET)

    messages = set()
    for bad in (expired, wrong_key, "garbage"):
        with pytest.raises(TokenError) as exc:
            verify(bad)
        messages.add(str(exc.value))

    assert len(messages) == 1, f"error messages leak the failure cause: {messages}"
