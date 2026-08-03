"""Refresh-token rotation and reuse detection.

The mandated negative case is `test_replaying_a_consumed_token_revokes_the_family`:
a stolen refresh token must not merely be rejected — the entire family has to
be revoked, because the server cannot tell the thief from the victim.

These tests use a real PostgreSQL session (as the schema owner, since token
lifecycle is not tenant-filtered at the RLS layer) so the flush and rowcount
behaviour matches production rather than a mock's.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from biovault.auth.refresh import (
    RefreshError,
    ReuseDetected,
    issue_initial_token,
    revoke_family,
    rotate,
)
from biovault.models.tables import RefreshToken

pytestmark = [pytest.mark.security, pytest.mark.integration]

TTL = 604800


def test_initial_token_is_issued_and_stored_hashed(owner_session) -> None:
    raw, family = issue_initial_token(
        owner_session, user_id="u-broad-research", tenant_id="lab-broad", ttl_seconds=TTL
    )

    stored = owner_session.execute(
        select(RefreshToken).where(RefreshToken.family_id == family)
    ).scalar_one()

    assert raw not in stored.token_hash, "raw token must not be stored"
    assert len(stored.token_hash) == 64, "expected a SHA-256 hex digest"
    assert stored.used_at is None
    assert stored.revoked_at is None


def test_rotation_issues_a_new_token_in_the_same_family(owner_session) -> None:
    raw, family = issue_initial_token(
        owner_session, user_id="u-broad-research", tenant_id="lab-broad", ttl_seconds=TTL
    )

    successor_raw, successor = rotate(owner_session, presented_token=raw, ttl_seconds=TTL)

    assert successor_raw != raw
    assert successor.family_id == family


def test_rotation_marks_the_presented_token_consumed(owner_session) -> None:
    raw, _ = issue_initial_token(
        owner_session, user_id="u-broad-research", tenant_id="lab-broad", ttl_seconds=TTL
    )
    rotate(owner_session, presented_token=raw, ttl_seconds=TTL)

    import hashlib

    consumed = owner_session.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == hashlib.sha256(raw.encode()).hexdigest()
        )
    ).scalar_one()
    assert consumed.used_at is not None


# --- MANDATED: reuse detection ----------------------------------------------


def test_replaying_a_consumed_token_revokes_the_family(owner_session) -> None:
    """The mandated case: replay must revoke the whole family, not just fail.

    Scenario: an attacker steals refresh token T1 and uses it. The legitimate
    client later presents T1 too. The server cannot tell which party is which,
    so it revokes everything descended from that login and forces both to
    re-authenticate.
    """
    raw_1, family = issue_initial_token(
        owner_session, user_id="u-broad-research", tenant_id="lab-broad", ttl_seconds=TTL
    )
    raw_2, _ = rotate(owner_session, presented_token=raw_1, ttl_seconds=TTL)

    with pytest.raises(ReuseDetected):
        rotate(owner_session, presented_token=raw_1, ttl_seconds=TTL)

    family_tokens = owner_session.execute(
        select(RefreshToken).where(RefreshToken.family_id == family)
    ).scalars().all()

    assert family_tokens, "family should not be empty"
    assert all(t.revoked_at is not None for t in family_tokens), (
        "every token in the family must be revoked after reuse"
    )


def test_successor_is_unusable_after_reuse_revokes_the_family(owner_session) -> None:
    """The attacker's freshly-minted token must die with the family.

    Without this, detecting reuse would be pointless: the thief already holds
    a valid successor and would keep using it.
    """
    raw_1, _ = issue_initial_token(
        owner_session, user_id="u-broad-research", tenant_id="lab-broad", ttl_seconds=TTL
    )
    raw_2, _ = rotate(owner_session, presented_token=raw_1, ttl_seconds=TTL)

    with pytest.raises(ReuseDetected):
        rotate(owner_session, presented_token=raw_1, ttl_seconds=TTL)

    with pytest.raises(RefreshError):
        rotate(owner_session, presented_token=raw_2, ttl_seconds=TTL)


def test_reuse_detection_survives_a_long_rotation_chain(owner_session) -> None:
    """Replaying an ancestor from deep in the chain still kills the family."""
    raw, family = issue_initial_token(
        owner_session, user_id="u-broad-research", tenant_id="lab-broad", ttl_seconds=TTL
    )
    first = raw
    for _ in range(5):
        raw, _ = rotate(owner_session, presented_token=raw, ttl_seconds=TTL)

    with pytest.raises(ReuseDetected):
        rotate(owner_session, presented_token=first, ttl_seconds=TTL)

    tokens = owner_session.execute(
        select(RefreshToken).where(RefreshToken.family_id == family)
    ).scalars().all()
    # Initial token plus five successors. The replay attempt mints nothing —
    # reuse is detected before a successor is issued, which is the point.
    assert len(tokens) == 6
    assert all(t.revoked_at is not None for t in tokens)


def test_reuse_of_an_expired_token_still_revokes_the_family(owner_session) -> None:
    """Expiry must not short-circuit reuse detection.

    An expired-and-replayed token is still evidence of theft. Checking expiry
    first and returning "expired" would discard that signal.
    """
    past = datetime.now(UTC) - timedelta(days=30)
    raw, family = issue_initial_token(
        owner_session,
        user_id="u-broad-research",
        tenant_id="lab-broad",
        ttl_seconds=60,
        now=past,
    )
    rotate(owner_session, presented_token=raw, ttl_seconds=60, now=past)

    with pytest.raises(ReuseDetected):
        rotate(owner_session, presented_token=raw, ttl_seconds=60)

    tokens = owner_session.execute(
        select(RefreshToken).where(RefreshToken.family_id == family)
    ).scalars().all()
    assert all(t.revoked_at is not None for t in tokens)


# --- Other rejection paths --------------------------------------------------


def test_unknown_token_is_rejected(owner_session) -> None:
    with pytest.raises(RefreshError):
        rotate(owner_session, presented_token="never-issued-token", ttl_seconds=TTL)


def test_expired_token_is_rejected(owner_session) -> None:
    past = datetime.now(UTC) - timedelta(days=30)
    raw, _ = issue_initial_token(
        owner_session,
        user_id="u-broad-research",
        tenant_id="lab-broad",
        ttl_seconds=60,
        now=past,
    )
    with pytest.raises(RefreshError):
        rotate(owner_session, presented_token=raw, ttl_seconds=TTL)


def test_explicitly_revoked_family_cannot_rotate(owner_session) -> None:
    raw, family = issue_initial_token(
        owner_session, user_id="u-broad-research", tenant_id="lab-broad", ttl_seconds=TTL
    )
    revoke_family(owner_session, family_id=family)

    with pytest.raises(RefreshError):
        rotate(owner_session, presented_token=raw, ttl_seconds=TTL)


def test_revoke_family_reports_how_many_it_revoked(owner_session) -> None:
    raw, family = issue_initial_token(
        owner_session, user_id="u-broad-research", tenant_id="lab-broad", ttl_seconds=TTL
    )
    raw, _ = rotate(owner_session, presented_token=raw, ttl_seconds=TTL)

    assert revoke_family(owner_session, family_id=family) == 2


def test_families_are_independent(owner_session) -> None:
    """Revoking one login must not sign the user out of their other sessions."""
    raw_a, family_a = issue_initial_token(
        owner_session, user_id="u-broad-research", tenant_id="lab-broad", ttl_seconds=TTL
    )
    raw_b, family_b = issue_initial_token(
        owner_session, user_id="u-broad-research", tenant_id="lab-broad", ttl_seconds=TTL
    )
    assert family_a != family_b

    rotate(owner_session, presented_token=raw_a, ttl_seconds=TTL)
    with pytest.raises(ReuseDetected):
        rotate(owner_session, presented_token=raw_a, ttl_seconds=TTL)

    successor_b, _ = rotate(owner_session, presented_token=raw_b, ttl_seconds=TTL)
    assert successor_b, "unrelated family must survive"


def test_raw_tokens_are_high_entropy_and_unique(owner_session) -> None:
    """Guessable refresh tokens would make rotation irrelevant."""
    tokens = {
        issue_initial_token(
            owner_session, user_id="u-broad-research", tenant_id="lab-broad", ttl_seconds=TTL
        )[0]
        for _ in range(100)
    }
    assert len(tokens) == 100
    assert all(len(t) >= 40 for t in tokens)
