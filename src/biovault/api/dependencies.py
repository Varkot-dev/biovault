"""FastAPI dependencies for authentication and tenant-scoped sessions.

The `Principal` is assembled here from verified token claims and nothing else.
Every field — tenant, role, grants, PHI clearance — comes from the signed JWT.
Reading any of them from a header, query parameter, or request body would be
the privilege-escalation vulnerability the whole authorization design exists to
prevent, so there is deliberately no code path that does.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from biovault.auth.tokens import TokenError, verify_access_token
from biovault.authz.policy import Principal
from biovault.config import Settings, get_settings
from biovault.db.session import tenant_session

# Uniform failure. Distinguishing "expired" from "bad signature" in a response
# is an oracle, matching the reasoning in auth.tokens.
_UNAUTHENTICATED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="invalid or missing credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_current_principal(
    authorization: Annotated[str | None, Header()] = None,
    settings: Annotated[Settings, Depends(get_settings)] = None,  # noqa: B008
) -> Principal:
    """Build a `Principal` from the bearer token.

    Raises:
        HTTPException: 401 on any authentication failure.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise _UNAUTHENTICATED

    token = authorization[len("bearer ") :].strip()
    if not token:
        raise _UNAUTHENTICATED

    try:
        claims = verify_access_token(
            token,
            secret=settings.jwt_secret.get_secret_value(),
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
        )
    except TokenError as exc:
        raise _UNAUTHENTICATED from exc

    return Principal(
        user_id=claims.subject,
        tenant_id=claims.tenant_id,
        role=claims.role,
        dataset_grants=claims.dataset_grants,
        phi_cleared=claims.phi_cleared,
    )


def get_tenant_session(
    principal: Annotated[Principal, Depends(get_current_principal)],
) -> Iterator[Session]:
    """Yield a session bound to the principal's tenant.

    The tenant comes from the verified token, so RLS is scoped by the same
    value the application-layer policy uses. The two layers agree because they
    read the same trusted source — but they enforce independently, which is
    what makes either one failing non-fatal.
    """
    with tenant_session(principal.tenant_id) as session:
        yield session


CurrentPrincipal = Annotated[Principal, Depends(get_current_principal)]
TenantSession = Annotated[Session, Depends(get_tenant_session)]
