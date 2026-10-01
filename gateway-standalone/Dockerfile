# The gateway, as the customer zone runs it.
#
# Build from the repo root: docker build -f gateway-standalone/Dockerfile .
# Files sent to the build: Dockerfile.dockerignore, next to this file.
FROM python:3.12-slim AS builder
# Exact version and digest: the image is built from uv.lock, and the tool that
# reads the lock is as much a part of the build as what is in it.
COPY --from=ghcr.io/astral-sh/uv:0.12.21@sha256:a7aed3216253ee804de3e2d8afa5073baa1a177335345d43845cd4165e43b711 /uv /bin/uv
# Compile .pyc now (the runtime user can't write them later); copy from the
# cache mount (no hardlinks across filesystems); use the image's Python, never a
# downloaded one, so the runtime stage below has the interpreter the venv names.
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=0
WORKDIR /app

# Step 1: third-party dependencies only, cached until the lockfile or a
# pyproject.toml changes. `--frozen` installs what uv.lock says and resolves
# nothing.
COPY pyproject.toml uv.lock ./
COPY gateway-core/pyproject.toml gateway-core/
COPY gateway-standalone/pyproject.toml gateway-standalone/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --package gateway-standalone --no-install-workspace

# Step 2: our code, installed into the venv (not editable), so the runtime
# stage needs only .venv.
COPY gateway-core gateway-core
COPY gateway-standalone gateway-standalone
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --package gateway-standalone --no-editable

FROM python:3.12-slim

WORKDIR /app

# The licence travels with the distribution. An image is a way of shipping this
# software, and Apache-2.0 asks that recipients get a copy.
COPY LICENSE NOTICE ./
COPY --from=builder /app/.venv /app/.venv
# The venv first, so `python` is the one holding the gateway and its
# dependencies — including for a command that overrides the CMD below.
ENV PATH="/app/.venv/bin:$PATH"

# python:3.12-slim defines no non-root user. Nothing past the install step needs
# root, and this process listens on a network for agents it is placed in front
# of precisely because they are not trusted.
RUN useradd --system --no-create-home --uid 10001 railgateway
USER 10001

# The default, which is all this can state: RAIL_GATEWAY_PORT moves the socket
# and EXPOSE is metadata rather than a binding, so `docker run -P` on a
# container that was given another port publishes the wrong one.
EXPOSE 8080

# The module's own entry point rather than a uvicorn command line, so that
# RAIL_GATEWAY_PORT reaches the socket. Naming the port here instead would have
# it validated and then ignored.
#
# Exec form: python is PID 1 and receives SIGTERM directly rather than waiting
# out docker's ten seconds. What happens next is uvicorn's default and not
# something this image sets — `main()` says why the drain is not bounded there.
#
# CMD rather than ENTRYPOINT, so a `command:` that replaces it — e2e's
# `sleep infinity` — runs that command instead of being handed to the gateway
# as arguments.
CMD ["python", "-m", "gateway.standalone.server"]
