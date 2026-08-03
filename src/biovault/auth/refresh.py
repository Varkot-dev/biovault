"""Refresh-token rotation with reuse detection.

Each login starts a token *family*. Every refresh consumes the presented token
and issues a successor in the same family. A token is therefore valid exactly
once.

Presenting an already-consumed token is the signal that matters. In normal
operation it cannot happen: the legitimate client discarded that token when it
received the successor. So a replay means the token was captured — either the
attacker is replaying it, or the legitimate client is replaying one the
attacker already used. Since the two cases are indistinguishable from the
server's position, the whole family is revoked and both parties are forced to
re-authenticate.

Tokens are stored as SHA-256 hashes. A database disclosure therefore yields no
usable tokens, the same reasoning that applies to password storage — though
unlike passwords these are already high-entropy, so a plain hash suffices and
a slow KDF would only add latency.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Final

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from biovault.models.tables import RefreshToken

TOKEN_BYTES: Final[int] = 32


class RefreshError(Exception):
    """Raised when a refresh token is invalid, expired, revoked, or replayed."""


class ReuseDetected(RefreshError):
    """Raised when an already-consumed token is presented again.

    Distinct from `RefreshError` so the API can log this specific event as a
    security incident. The distinction is deliberately *not* surfaced in the
    HTTP response, which returns the same generic failure either way.
    """


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()


def issue_initial_token(
    session: Session,
    *,
    user_id: str,
    tenant_id: str,
    ttl_seconds: int,
    now: datetime | None = None,
) -> tuple[str, str]:
    """Start a new token family at login.

    Returns:
        The raw token (returned to the client once, never stored) and its
        family id.
    """
    issued_at = now or datetime.now(UTC)
    raw_token = secrets.token_urlsafe(TOKEN_BYTES)
    family_id = secrets.token_urlsafe(16)

    session.add(
        RefreshToken(
            family_id=family_id,
            user_id=user_id,
            tenant_id=tenant_id,
            token_hash=_hash_token(raw_token),
            expires_at=issued_at + timedelta(seconds=ttl_seconds),
        )
    )
    session.flush()
    return raw_token, family_id


def rotate(
    session: Session,
    *,
    presented_token: str,
    ttl_seconds: int,
    now: datetime | None = None,
) -> tuple[str, RefreshToken]:
    """Consume a refresh token and issue its successor.

    Raises:
        ReuseDetected: The token was already consumed. The family is revoked
            before this is raised.
        RefreshError: The token is unknown, expired, or belongs to a revoked
            family.
    """
    current = now or datetime.now(UTC)
    token_hash = _hash_token(presented_token)

    stored = session.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    ).scalar_one_or_none()

    if stored is None:
        raise RefreshError("refresh token not recognised")

    # Reuse detection runs before every other check. An expired-and-reused
    # token is still evidence of theft, so the family must be revoked rather
    # than the request merely rejected as expired.
    if stored.used_at is not None:
        revoke_family(session, family_id=stored.family_id, now=current)
        raise ReuseDetected("refresh token replayed; family revoked")

    if stored.revoked_at is not None:
        raise RefreshError("refresh token belongs to a revoked family")

    if _as_utc(stored.expires_at) <= current:
        raise RefreshError("refresh token expired")

    stored.used_at = current

    successor_raw = secrets.token_urlsafe(TOKEN_BYTES)
    successor = RefreshToken(
        family_id=stored.family_id,
        user_id=stored.user_id,
        tenant_id=stored.tenant_id,
        token_hash=_hash_token(successor_raw),
        expires_at=current + timedelta(seconds=ttl_seconds),
    )
    session.add(successor)
    session.flush()

    return successor_raw, successor


def revoke_family(session: Session, *, family_id: str, now: datetime | None = None) -> int:
    """Revoke every token in a family. Returns the number revoked.

    Revokes the entire family rather than one token because the attacker may
    hold any descendant, and the server cannot tell which party is legitimate.
    """
    current = now or datetime.now(UTC)
    result = session.execute(
        update(RefreshToken)
        .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=current)
    )
    session.flush()
    return result.rowcount


def _as_utc(value: datetime) -> datetime:
    """Normalise a possibly-naive timestamp to UTC.

    Guards against comparing a naive value from the database against an
    aware one, which raises rather than returning a wrong answer — but only
    at runtime, so normalising here is safer.
    """
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
