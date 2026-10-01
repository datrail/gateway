# Build from the repo root: docker build -f gateway-standalone/Dockerfile .
# What is sent to the build is limited by Dockerfile.dockerignore, next to this file.
FROM python:3.12-slim AS builder
# Pinned by digest: uv is part of the build, like the lockfile it reads.
COPY --from=ghcr.io/astral-sh/uv:0.12.21@sha256:a7aed3216253ee804de3e2d8afa5073baa1a177335345d43845cd4165e43b711 /uv /bin/uv
# Precompile .pyc (the runtime user can't write them); copy rather than hardlink
# from the cache mount; use the base image's Python, which the runtime stage has too.
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=0
WORKDIR /app

# Third-party dependencies first, cached until uv.lock or a pyproject.toml changes.
COPY pyproject.toml uv.lock ./
COPY gateway-core/pyproject.toml gateway-core/
COPY gateway-standalone/pyproject.toml gateway-standalone/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --package gateway-standalone --no-install-workspace

# Then our code, installed (not editable) so the runtime stage needs only .venv.
COPY gateway-core gateway-core
COPY gateway-standalone gateway-standalone
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --package gateway-standalone --no-editable

FROM python:3.12-slim

WORKDIR /app

# Apache-2.0 asks that recipients get a copy of the licence.
COPY LICENSE NOTICE ./
COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

# Non-root: the gateway faces untrusted agents.
RUN useradd --system --no-create-home --uid 10001 railgateway
USER 10001

# The default port; RAIL_GATEWAY_PORT changes it.
EXPOSE 8080

# Exec form, so python is PID 1 and receives SIGTERM. CMD rather than ENTRYPOINT,
# so a replacement command runs as given. The module's own entry point, rather than
# a uvicorn command line, is what reads RAIL_GATEWAY_PORT.
CMD ["python", "-m", "gateway.standalone.server"]
