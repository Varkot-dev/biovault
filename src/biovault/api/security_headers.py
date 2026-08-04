"""Security response headers.

Each header below closes a specific attack. The cache-control pair matters most
for this API: without it, an intermediary proxy or browser may store decrypted
genomic responses on disk, undoing encryption-at-rest the moment data leaves
the database.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Final

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# Applied to every response.
_BASE_HEADERS: Final[dict[str, str]] = {
    # Stop MIME sniffing turning a JSON body into executable content.
    "X-Content-Type-Options": "nosniff",
    # This is a JSON API; it should never be framed.
    "X-Frame-Options": "DENY",
    # Do not leak dataset identifiers in the Referer of an outbound link.
    "Referrer-Policy": "no-referrer",
    # Deny device APIs outright; an API has no use for them.
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
    # No inline content is served, so a maximally restrictive CSP costs nothing
    # and mitigates any future accidental HTML rendering.
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    # Hide the server implementation from trivial fingerprinting.
    "Server": "biovault",
}

# Applied to responses that may contain genomic data.
_NO_STORE_HEADERS: Final[dict[str, str]] = {
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
    "Pragma": "no-cache",
}

# Paths safe to cache: no authentication, no tenant data.
_CACHEABLE_PATHS: Final[frozenset[str]] = frozenset({"/health", "/docs", "/openapi.json", "/redoc"})

# HSTS is only meaningful over HTTPS and actively harmful to local development
# over plain HTTP, so it is emitted only when the request arrived as HTTPS.
_HSTS_VALUE: Final[str] = "max-age=31536000; includeSubDomains"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach hardening headers to every response."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)

        for header, value in _BASE_HEADERS.items():
            response.headers[header] = value

        if request.url.path not in _CACHEABLE_PATHS:
            # Default to no-store. Anything not explicitly marked cacheable is
            # assumed to carry tenant data — the safe direction for a genomics
            # API, where a cached response on a shared proxy is a disclosure.
            for header, value in _NO_STORE_HEADERS.items():
                response.headers[header] = value

        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = _HSTS_VALUE

        return response
