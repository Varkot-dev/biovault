"""OAuth 2.0 endpoints: authorize, token, refresh.

These run without a tenant-bound session. Tenant context cannot be established
before the user is identified, and the tables involved — `authorization_codes`
and `refresh_tokens` — are deliberately not tenant-scoped for that reason.
Both are keyed by unguessable high-entropy values, so the absence of RLS on
them is not a hole: there is no identifier an attacker can enumerate.

Every failure returns an identical 400 or 401. Distinguishing "unknown code"
from "wrong verifier" from "expired" would let an attacker probe which part of
a guess was right.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from biovault.api.rate_limit import limiter
from biovault.auth.authorization_code import (
    CODE_TTL_SECONDS,
    AuthorizationError,
    issue_authorization_code,
    redeem_authorization_code,
)
from biovault.auth.refresh import (
    RefreshError,
    ReuseDetected,
    issue_initial_token,
    rotate,
)
from biovault.auth.tokens import issue_access_token
from biovault.authz.policy import Role
from biovault.config import get_settings
from biovault.db.rls import set_tenant_context
from biovault.db.session import untenanted_session
from biovault.models.tables import DatasetGrant, User
from biovault.schemas.auth import (
    AuthorizeRequest,
    AuthorizeResponse,
    RefreshRequest,
    TokenRequest,
    TokenResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

_INVALID_GRANT = HTTPException(
    status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_grant"
)
_INVALID_CLIENT = HTTPException(
    status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_client"
)


def _load_grants(session: Session, user: User) -> frozenset[str]:
    """Read a user's dataset grants, binding their tenant first.

    `dataset_grants` is tenant-scoped, so an untenanted session sees zero rows.
    Once the user has been identified their tenant *is* known, so the correct
    fix is to bind it here rather than widen the grants policy — the identity
    lookup needed an exception, this does not.

    Grants are read server-side at token-issue time and baked into the signed
    token. They are never accepted from the client.
    """
    set_tenant_context(session.connection(), user.tenant_id)
    rows = session.execute(
        select(DatasetGrant.dataset_id).where(DatasetGrant.user_id == user.id)
    ).scalars().all()
    return frozenset(rows)


def _issue_token_pair(session: Session, user: User) -> TokenResponse:
    """Mint an access/refresh pair for an authenticated user."""
    settings = get_settings()
    grants = _load_grants(session, user)

    access = issue_access_token(
        subject=user.id,
        tenant_id=user.tenant_id,
        role=Role(user.role),
        dataset_grants=grants,
        phi_cleared=user.phi_cleared,
        secret=settings.jwt_secret.get_secret_value(),
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        ttl_seconds=settings.access_token_ttl_seconds,
    )
    refresh, _ = issue_initial_token(
        session,
        user_id=user.id,
        tenant_id=user.tenant_id,
        ttl_seconds=settings.refresh_token_ttl_seconds,
    )
    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.access_token_ttl_seconds,
    )


@router.post("/authorize", response_model=AuthorizeResponse)
@limiter.limit(lambda: get_settings().rate_limit)
def authorize(request: Request, payload: AuthorizeRequest) -> AuthorizeResponse:
    """Issue an authorization code bound to a PKCE challenge.

    A production deployment performs interactive login and consent before this
    point; see the README's "what this isn't".
    """
    settings = get_settings()

    if payload.client_id != settings.oauth_client_id:
        raise _INVALID_CLIENT
    if payload.redirect_uri != settings.oauth_redirect_uri:
        # An unregistered redirect URI is where a stolen code would be
        # delivered, so this must be an exact match against configuration.
        raise _INVALID_CLIENT

    with untenanted_session() as session:
        user = session.execute(
            select(User).where(User.id == payload.user_id)
        ).scalar_one_or_none()
        if user is None:
            # Same error as a bad client: revealing which user ids exist would
            # turn this endpoint into an account-enumeration oracle.
            raise _INVALID_CLIENT

        try:
            code = issue_authorization_code(
                session,
                user_id=user.id,
                client_id=payload.client_id,
                redirect_uri=payload.redirect_uri,
                code_challenge=payload.code_challenge,
                code_challenge_method=payload.code_challenge_method,
            )
        except AuthorizationError as exc:
            raise _INVALID_GRANT from exc

    return AuthorizeResponse(code=code, expires_in=CODE_TTL_SECONDS)


@router.post("/token", response_model=TokenResponse)
@limiter.limit(lambda: get_settings().rate_limit)
def exchange_code(request: Request, payload: TokenRequest) -> TokenResponse:
    """Redeem an authorization code plus PKCE verifier for tokens."""
    with untenanted_session() as session:
        try:
            user = redeem_authorization_code(
                session,
                code=payload.code,
                code_verifier=payload.code_verifier,
                client_id=payload.client_id,
                redirect_uri=payload.redirect_uri,
            )
        except AuthorizationError as exc:
            raise _INVALID_GRANT from exc

        return _issue_token_pair(session, user)


@router.post("/refresh", response_model=TokenResponse)
@limiter.limit(lambda: get_settings().rate_limit)
def refresh_tokens(request: Request, payload: RefreshRequest) -> TokenResponse:
    """Rotate a refresh token, issuing a new access/refresh pair.

    Reuse of an already-consumed token revokes the whole family. The client
    sees the same generic failure as any other invalid token — telling an
    attacker their replay was *detected* would tell them the account is being
    watched.
    """
    settings = get_settings()

    with untenanted_session() as session:
        try:
            new_refresh, stored = rotate(
                session,
                presented_token=payload.refresh_token,
                ttl_seconds=settings.refresh_token_ttl_seconds,
            )
        except ReuseDetected as exc:
            # Logged at ERROR: a replay means a token was captured. This is an
            # incident, not routine authentication failure.
            logger.error(
                "refresh token reuse detected; family revoked (client=%s)",
                request.client.host if request.client else "unknown",
            )
            raise _INVALID_GRANT from exc
        except RefreshError as exc:
            raise _INVALID_GRANT from exc

        user = session.execute(
            select(User).where(User.id == stored.user_id)
        ).scalar_one_or_none()
        if user is None:
            raise _INVALID_GRANT

        grants = _load_grants(session, user)
        access = issue_access_token(
            subject=user.id,
            tenant_id=user.tenant_id,
            role=Role(user.role),
            dataset_grants=grants,
            phi_cleared=user.phi_cleared,
            secret=settings.jwt_secret.get_secret_value(),
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            ttl_seconds=settings.access_token_ttl_seconds,
        )

        return TokenResponse(
            access_token=access,
            refresh_token=new_refresh,
            expires_in=settings.access_token_ttl_seconds,
        )
