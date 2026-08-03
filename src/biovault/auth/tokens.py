"""JWT issuance and verification.

Verification is deliberately strict. Every check below exists because its
absence is a known, exploited vulnerability class:

- **Explicit algorithm allowlist.** Never trust the token's own `alg` header.
  Accepting `none` lets anyone mint a valid token; accepting `HS256` where
  `RS256` was intended lets an attacker sign with the public key.
- **Audience and issuer.** Without them, a token minted by a different service
  that happens to share a signing key is accepted here.
- **Expiry, with no leeway.** A grace period is a deliberate extension of a
  stolen token's lifetime.
- **Required claims.** A token missing `sub` or `tenant` must be rejected
  rather than defaulting to something.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Final

import jwt
from pydantic import BaseModel, ConfigDict

from biovault.authz.policy import Role

# The only algorithm this service will accept. Passed explicitly to
# jwt.decode so the token header cannot influence verification.
ALLOWED_ALGORITHMS: Final[tuple[str, ...]] = ("HS256",)

# Value of the `typ` claim. Not a secret: it discriminates access tokens from
# refresh tokens so the two cannot be substituted for one another.
TOKEN_TYPE_ACCESS: Final[str] = "access"  # noqa: S105
REQUIRED_CLAIMS: Final[tuple[str, ...]] = ("sub", "exp", "iat", "iss", "aud", "tenant", "role")


class TokenError(Exception):
    """Raised when a token is absent, malformed, expired, or fails verification.

    Carries no detail about which check failed, for the same reason
    `DecryptionError` does not: distinguishing "expired" from "bad signature"
    in a response body is an oracle.
    """


class AccessTokenClaims(BaseModel):
    """Verified claims from an access token.

    A `Principal` is built from this and nothing else. Any field sourced from
    the request body or query string instead would be attacker-controlled —
    that substitution is the privilege-escalation bug this type exists to
    prevent.
    """

    model_config = ConfigDict(frozen=True)

    subject: str
    tenant_id: str
    role: Role
    phi_cleared: bool
    dataset_grants: frozenset[str]
    expires_at: datetime


def issue_access_token(
    *,
    subject: str,
    tenant_id: str,
    role: Role,
    dataset_grants: frozenset[str],
    phi_cleared: bool,
    secret: str,
    issuer: str,
    audience: str,
    ttl_seconds: int,
    now: datetime | None = None,
) -> str:
    """Mint a signed access token.

    `now` is injectable so expiry behaviour can be tested without sleeping.
    """
    issued_at = now or datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": subject,
        "iss": issuer,
        "aud": audience,
        "iat": issued_at,
        "exp": issued_at + timedelta(seconds=ttl_seconds),
        "typ": TOKEN_TYPE_ACCESS,
        "tenant": tenant_id,
        "role": role.value,
        "phi_cleared": phi_cleared,
        "grants": sorted(dataset_grants),
    }
    return jwt.encode(payload, secret, algorithm=ALLOWED_ALGORITHMS[0])


def verify_access_token(
    token: str,
    *,
    secret: str,
    issuer: str,
    audience: str,
) -> AccessTokenClaims:
    """Verify a token and return its claims.

    Raises:
        TokenError: On any verification failure — bad signature, expiry,
            wrong audience or issuer, disallowed algorithm, missing claims,
            or wrong token type.
    """
    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=list(ALLOWED_ALGORITHMS),
            audience=audience,
            issuer=issuer,
            options={
                "require": list(REQUIRED_CLAIMS),
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
            },
            leeway=0,
        )
    except jwt.InvalidTokenError as exc:
        raise TokenError("token verification failed") from exc

    # A refresh token presented as an access token must be rejected: refresh
    # tokens live longer, so accepting one here would silently extend session
    # lifetime well past the access-token TTL.
    if payload.get("typ") != TOKEN_TYPE_ACCESS:
        raise TokenError("token verification failed")

    try:
        role = Role(payload["role"])
    except ValueError as exc:
        raise TokenError("token verification failed") from exc

    grants = payload.get("grants", [])
    if not isinstance(grants, list) or not all(isinstance(g, str) for g in grants):
        raise TokenError("token verification failed")

    return AccessTokenClaims(
        subject=payload["sub"],
        tenant_id=payload["tenant"],
        role=role,
        phi_cleared=bool(payload.get("phi_cleared", False)),
        dataset_grants=frozenset(grants),
        expires_at=datetime.fromtimestamp(payload["exp"], tz=UTC),
    )
