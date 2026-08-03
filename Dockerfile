# syntax=docker/dockerfile:1

FROM python:3.13-slim AS base

# Build stage: install into a virtualenv that gets copied forward, so build
# tooling never reaches the runtime image.
FROM base AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

# Runtime stage
FROM base AS runtime

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Run as an unprivileged user. A container process running as root that is
# compromised has a materially easier path to escaping to the host.
RUN useradd --create-home --uid 10001 biovault

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
USER biovault

EXPOSE 8000

# No secrets are baked in. Every credential arrives through the environment at
# run time; see .env.example and docker-compose.yml.
CMD ["uvicorn", "biovault.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
