"""OAuth 2.0 authorization-code issuance and redemption.

Codes are single-use, short-lived, and bound to four things that must all match
at redemption: the PKCE challenge, the client id, the redirect URI, and the
code's own expiry. Each binding closes a distinct attack:

- **PKCE challenge** — an intercepted code is useless without the verifier,
  which never left the legitimate client.
- **client_id** — stops a different registered client redeeming another
  client's code.
- **redirect_uri** — RFC 6749 section 4.1.3 requires it to match the
  authorization request. Without the check, an attacker who can register a
  redirect can have the code delivered to themselves.
- **Single use** — redemption marks the code consumed. Replay is refused.

Codes are stored hashed for the same reason refresh tokens are: a database
disclosure must not yield redeemable credentials.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from biovault.auth.pkce import METHOD_S256, PkceError, verify_challenge
from biovault.models.tables import AuthorizationCode, User

CODE_BYTES: Final[int] = 32

# Authorization codes are redeemed within seconds by a well-behaved client.
# RFC 6749 section 4.1.2 recommends a maximum of 10 minutes; 60 seconds is
# ample for the exchange and shrinks the window for a stolen code.
CODE_TTL_SECONDS: Final[int] = 60


class AuthorizationError(Exception):
    """Raised when a code cannot be issued or redeemed.

    Uniform message, no detail about which binding failed — the same
    no-oracle reasoning as TokenError and DecryptionError.
    """


def _hash_code(raw_code: str) -> str:
    return hashlib.sha256(raw_code.encode()).hexdigest()


def issue_authorization_code(
    session: Session,
    *,
    user_id: str,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str,
    now: datetime | None = None,
) -> str:
    """Issue a code bound to a PKCE challenge.

    Returns:
        The raw code, returned to the client once and never stored.

    Raises:
        AuthorizationError: If the challenge method is unsupported or the
            challenge is malformed.
    """
    if code_challenge_method != METHOD_S256:
        raise AuthorizationError("unsupported code_challenge_method")
    if not code_challenge or len(code_challenge) > 128:
        raise AuthorizationError("invalid code_challenge")

    issued_at = now or datetime.now(UTC)
    raw_code = secrets.token_urlsafe(CODE_BYTES)

    session.add(
        AuthorizationCode(
            code_hash=_hash_code(raw_code),
            user_id=user_id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=issued_at + timedelta(seconds=CODE_TTL_SECONDS),
        )
    )
    session.flush()
    return raw_code


def redeem_authorization_code(
    session: Session,
    *,
    code: str,
    code_verifier: str,
    client_id: str,
    redirect_uri: str,
    now: datetime | None = None,
) -> User:
    """Consume a code and return the user it authenticates.

    Every binding is checked before the code is marked consumed, and the code
    is consumed before the user is returned, so a failure part-way through
    cannot leave a redeemable code behind.

    Raises:
        AuthorizationError: On any failure — unknown, expired, already
            consumed, wrong client, wrong redirect URI, or bad verifier.
    """
    current = now or datetime.now(UTC)

    stored = session.execute(
        select(AuthorizationCode).where(AuthorizationCode.code_hash == _hash_code(code))
    ).scalar_one_or_none()

    if stored is None:
        raise AuthorizationError("authorization code is not valid")

    if stored.consumed_at is not None:
        raise AuthorizationError("authorization code is not valid")

    if _as_utc(stored.expires_at) <= current:
        raise AuthorizationError("authorization code is not valid")

    # Constant-time comparison on both bindings. These are not secrets in the
    # strictest sense, but a timing difference still reveals how much of a
    # guessed value was correct.
    if not hmac.compare_digest(stored.client_id, client_id):
        raise AuthorizationError("authorization code is not valid")

    if not hmac.compare_digest(stored.redirect_uri, redirect_uri):
        raise AuthorizationError("authorization code is not valid")

    try:
        verify_challenge(
            code_verifier=code_verifier,
            code_challenge=stored.code_challenge,
            method=stored.code_challenge_method,
        )
    except PkceError as exc:
        raise AuthorizationError("authorization code is not valid") from exc

    stored.consumed_at = current
    session.flush()

    user = session.execute(
        select(User).where(User.id == stored.user_id)
    ).scalar_one_or_none()
    if user is None:
        raise AuthorizationError("authorization code is not valid")

    return user


def _as_utc(value: datetime) -> datetime:
    """Normalise a possibly-naive timestamp to UTC before comparison."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
