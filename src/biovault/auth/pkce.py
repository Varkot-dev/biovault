"""PKCE (RFC 7636) verification for the authorization-code flow.

PKCE binds an authorization code to the client that requested it. Without it,
an attacker who intercepts a code — via a redirect leak, a malicious app
registered on the same URI scheme, or browser history — can exchange it for
tokens. With it, the exchange also requires the `code_verifier`, which never
left the legitimate client.

Only S256 is supported. The `plain` method RFC 7636 permits offers no
protection against an attacker who can already see the authorization request,
so it is refused rather than supported for compatibility.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from typing import Final

# RFC 7636 section 4.1: 43-128 characters from the unreserved set.
_VERIFIER_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")

METHOD_S256: Final[str] = "S256"


class PkceError(Exception):
    """Raised when a PKCE challenge/verifier pair fails validation."""


def derive_challenge(code_verifier: str) -> str:
    """Return the S256 challenge for a verifier.

    Raises:
        PkceError: If the verifier does not meet RFC 7636 requirements.
    """
    if not _VERIFIER_PATTERN.match(code_verifier):
        raise PkceError("code_verifier must be 43-128 unreserved characters")
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def verify_challenge(*, code_verifier: str, code_challenge: str, method: str) -> None:
    """Check a verifier against the stored challenge.

    Comparison is constant-time. A short-circuiting comparison would leak the
    expected challenge byte by byte under timing analysis.

    Raises:
        PkceError: If the method is unsupported or the verifier does not match.
    """
    if method != METHOD_S256:
        raise PkceError(f"unsupported code_challenge_method {method!r}; only S256 is allowed")

    expected = derive_challenge(code_verifier)
    if not hmac.compare_digest(expected, code_challenge):
        raise PkceError("code_verifier does not match code_challenge")
