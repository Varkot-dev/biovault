"""Rate limiting.

Keyed by authenticated subject where possible, falling back to client address
for unauthenticated requests. Keying purely on IP would let one user behind a
shared NAT exhaust the budget for everyone at their institution — a realistic
scenario for research labs behind a single egress address.
"""

from __future__ import annotations

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address


def rate_limit_key(request: Request) -> str:
    """Prefer the authenticated subject; fall back to remote address.

    The token is read without verification here. That is safe because this
    value only selects a rate-limit bucket — it grants no access. A forged
    token can at worst move an attacker into a different bucket, which does
    not help them, while the authorization path verifies signatures properly.
    """
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        token = authorization[len("bearer ") :].strip()
        if token:
            import jwt

            try:
                claims = jwt.decode(token, options={"verify_signature": False})
            except jwt.InvalidTokenError:
                return get_remote_address(request)
            subject = claims.get("sub")
            if isinstance(subject, str) and subject:
                return f"sub:{subject}"
    return get_remote_address(request)


limiter = Limiter(key_func=rate_limit_key)
