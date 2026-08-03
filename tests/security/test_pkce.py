"""PKCE (RFC 7636) verification tests.

PKCE exists to stop an intercepted authorization code from being redeemed by
anyone other than the client that requested it. These tests are written as
that attack: hold a stolen code, supply the wrong verifier, and confirm the
exchange fails.
"""

from __future__ import annotations

import base64
import hashlib
import secrets

import pytest

from biovault.auth.pkce import METHOD_S256, PkceError, derive_challenge, verify_challenge

pytestmark = pytest.mark.security


def make_verifier() -> str:
    return secrets.token_urlsafe(64)[:64]


def test_challenge_matches_rfc7636_s256_definition() -> None:
    """Challenge must be BASE64URL(SHA256(verifier)) with padding stripped.

    Computed independently here rather than by calling the implementation,
    so the test would catch the implementation changing to something that is
    self-consistent but not RFC-conformant — which would silently break
    interoperability with real OAuth clients.
    """
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .decode("ascii")
        .rstrip("=")
    )
    assert derive_challenge(verifier) == expected


def test_correct_verifier_passes() -> None:
    verifier = make_verifier()
    challenge = derive_challenge(verifier)
    verify_challenge(code_verifier=verifier, code_challenge=challenge, method=METHOD_S256)


def test_wrong_verifier_is_rejected() -> None:
    """The core attack: attacker holds the code but not the verifier."""
    challenge = derive_challenge(make_verifier())
    with pytest.raises(PkceError):
        verify_challenge(
            code_verifier=make_verifier(), code_challenge=challenge, method=METHOD_S256
        )


def test_plain_method_is_refused() -> None:
    """RFC 7636 permits `plain`, but it protects against nothing here.

    An attacker positioned to intercept the authorization code can also read
    the plaintext challenge in the authorization request, so `plain` provides
    no defence. Supporting it for compatibility would let a client downgrade
    itself out of protection.
    """
    verifier = make_verifier()
    with pytest.raises(PkceError, match="S256"):
        verify_challenge(code_verifier=verifier, code_challenge=verifier, method="plain")


@pytest.mark.parametrize("method", ["", "S512", "sha256", "s256", "NONE", "MD5"])
def test_unsupported_methods_are_refused(method: str) -> None:
    verifier = make_verifier()
    challenge = derive_challenge(verifier)
    with pytest.raises(PkceError):
        verify_challenge(code_verifier=verifier, code_challenge=challenge, method=method)


@pytest.mark.parametrize(
    "bad_verifier",
    [
        "",
        "short",
        "a" * 42,  # one below the RFC minimum
        "a" * 129,  # one above the RFC maximum
        "contains spaces in the verifier value padding to length" + "a" * 20,
        "contains/slash+plus=chars" + "a" * 30,
    ],
)
def test_malformed_verifiers_are_rejected(bad_verifier: str) -> None:
    """Length and charset limits come from RFC 7636 section 4.1.

    A too-short verifier is brute-forceable, which would defeat the mechanism.
    """
    with pytest.raises(PkceError):
        derive_challenge(bad_verifier)


def test_boundary_lengths_are_accepted() -> None:
    """43 and 128 characters are both valid per the RFC."""
    assert derive_challenge("a" * 43)
    assert derive_challenge("a" * 128)


def test_challenge_is_deterministic() -> None:
    verifier = make_verifier()
    assert derive_challenge(verifier) == derive_challenge(verifier)


def test_distinct_verifiers_produce_distinct_challenges() -> None:
    challenges = {derive_challenge(make_verifier()) for _ in range(100)}
    assert len(challenges) == 100


def test_challenge_has_no_base64_padding() -> None:
    """RFC 7636 requires padding to be stripped; `=` would break comparison."""
    assert "=" not in derive_challenge(make_verifier())


def test_truncated_challenge_is_rejected() -> None:
    """Guards against a comparison that only checks a prefix."""
    verifier = make_verifier()
    challenge = derive_challenge(verifier)
    with pytest.raises(PkceError):
        verify_challenge(
            code_verifier=verifier, code_challenge=challenge[:-1], method=METHOD_S256
        )


def test_empty_challenge_is_rejected() -> None:
    with pytest.raises(PkceError):
        verify_challenge(code_verifier=make_verifier(), code_challenge="", method=METHOD_S256)
