"""Request and response models for the OAuth 2.0 endpoints.

Field names follow RFC 6749 (`code_verifier`, `grant_type`, `redirect_uri`)
rather than the project's usual snake_case-by-convention, because real OAuth
clients send exactly these names.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AuthorizeRequest(BaseModel):
    """An authorization request carrying a PKCE challenge.

    In a full deployment this arrives after interactive login and consent.
    Here `user_id` stands in for the authenticated session — see the README's
    "what this isn't": there is no consent UI.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    response_type: Literal["code"] = "code"
    client_id: str = Field(min_length=1, max_length=128)
    redirect_uri: str = Field(min_length=1, max_length=500)
    code_challenge: str = Field(min_length=43, max_length=128)
    code_challenge_method: Literal["S256"] = "S256"
    user_id: str = Field(min_length=1, max_length=64)


class AuthorizeResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str
    expires_in: int


class TokenRequest(BaseModel):
    """Redemption of an authorization code for tokens."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    grant_type: Literal["authorization_code"] = "authorization_code"
    code: str = Field(min_length=1, max_length=256)
    code_verifier: str = Field(min_length=43, max_length=128)
    client_id: str = Field(min_length=1, max_length=128)
    redirect_uri: str = Field(min_length=1, max_length=500)


class RefreshRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    grant_type: Literal["refresh_token"] = "refresh_token"
    refresh_token: str = Field(min_length=1, max_length=256)


class TokenResponse(BaseModel):
    """RFC 6749 section 5.1 token response."""

    model_config = ConfigDict(frozen=True)

    access_token: str
    refresh_token: str
    # RFC 6749 section 5.1 token_type. A protocol constant, not a credential.
    token_type: Literal["Bearer"] = "Bearer"  # noqa: S105
    expires_in: int
