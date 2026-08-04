"""FastAPI application entry point."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from biovault.api.rate_limit import limiter
from biovault.api.routes import audit, auth, datasets, federation
from biovault.api.security_headers import SecurityHeadersMiddleware

logger = logging.getLogger(__name__)

app = FastAPI(
    title="BioVault",
    description="Role-based access control for multi-institution genomics datasets",
    version="0.1.0",
)

app.state.limiter = limiter
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(SlowAPIMiddleware)
app.include_router(auth.router)
app.include_router(datasets.router)
app.include_router(audit.router)
app.include_router(federation.router)


@app.exception_handler(RateLimitExceeded)
def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={"detail": "rate limit exceeded"},
    )


@app.exception_handler(Exception)
def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Return an opaque 500 while logging the detail server-side.

    Stack traces and exception messages routinely contain table names, query
    fragments, and file paths. Those belong in the server log, not in a
    response body an attacker can read.
    """
    logger.exception("unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "internal server error"})


@app.get("/health", tags=["ops"])
def health() -> dict[str, str]:
    """Liveness probe. Deliberately unauthenticated and free of detail."""
    return {"status": "ok"}
