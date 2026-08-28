"""Receive an agent's MCP calls and forward them to the service behind us.

This is the transport half. It decides nothing yet — a ticket is read in a
later change, a policy bundle fetched in the one after — so every request that
arrives is forwarded.

Three choices here are not obvious, and each has a way of being wrong that
nothing would report:

  * **The proxy is served directly, never mounted.** `FastMCP.mount` prefixes
    every tool it re-exposes with its namespace, so an upstream `track_package`
    reaches the agent as `up_track_package`. The sibling proxy wants that — it
    fronts several servers and the prefix is how an agent tells them apart.
    This component fronts exactly one and must be transparent: an endpoint key
    is `<datasource_slug>.<tool_name>`, and a renamed tool matches no endpoint
    the control plane registered while the agents were prompted with the real
    name.

  * **Incoming headers are not forwarded.** `create_proxy` turns that on. Left
    on, a caller can set `x-rail` itself and have it arrive upstream unchanged
    — so the identity this component exists to check would be supplied by the
    caller it exists to check. `authorization` rides the same path.

  * **Enforcement belongs above the MCP layer, not inside it.** A refusal is an
    HTTP status: 403 for a call that was judged and denied, 503 for one that
    could not be judged at all. Inside an MCP server a refusal is a JSON-RPC
    error instead, which the control plane's denial contract does not describe
    and an operator cannot read off a status line.
"""

from __future__ import annotations

import logging
import os

from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.server import create_proxy
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

log = logging.getLogger("gateway")

DEFAULT_PORT = 8080


def _required(name: str) -> str:
    """Read a variable that has no sensible default.

    Raising here rather than defaulting is deliberate: a gateway pointed at
    nothing forwards nothing, and it would report healthy while doing it.
    """
    value = (os.environ.get(name) or "").strip()
    if not value:
        raise RuntimeError(f"{name} is required and is unset or empty")
    return value


def port() -> int:
    """The port to listen on."""
    raw = (os.environ.get("RAIL_GATEWAY_PORT") or str(DEFAULT_PORT)).strip()
    try:
        value = int(raw)
    except ValueError:
        raise RuntimeError(
            f"RAIL_GATEWAY_PORT must be an integer, got: {raw}"
        ) from None
    if not 1 <= value <= 65535:
        raise RuntimeError(
            f"RAIL_GATEWAY_PORT must be between 1 and 65535, got: {value}"
        )
    return value


def build_gateway(upstream_url: str | None = None) -> FastMCP:
    """The proxy that forwards to the upstream, plus a liveness route."""
    url = upstream_url or _required("RAIL_GATEWAY_UPSTREAM_URL")

    transport = StreamableHttpTransport(url=url)
    gateway = create_proxy(Client(transport), name="datrail-gateway")

    # **After `create_proxy`, and it has to be.** `create_proxy` sets this True
    # itself, on the transport of any plain Client it is handed
    # (fastmcp/server/providers/proxy.py). Setting it before that call reads as
    # correct, is silently overwritten, and the tests that catch it are the two
    # asserting nothing of the caller's crosses — without them, reordering
    # these two lines is a tidy-up that reopens the hole.
    #
    # fastmcp's own comment says forwarding is "only appropriate for proxy
    # clients, where the caller's credentials should be propagated". That is the
    # opposite of what an enforcement point needs: the credentials arriving here
    # are what this component judges, not what it relays.
    transport.forward_incoming_headers = False

    @gateway.custom_route("/health", methods=["GET"])
    async def health(_request):  # pragma: no cover - exercised over HTTP
        """Liveness only: the process is up and its configuration parsed.

        It says nothing about whether this gateway can decide anything, because
        there is nothing to decide with yet. Once a policy bundle is held, a
        process holding none must stop reporting ready — otherwise whatever
        waits on this is released into the window where every call is refused.
        """
        return JSONResponse({"status": "ok"})

    log.info("forwarding to %s", url)
    return gateway


def build_app(upstream_url: str | None = None) -> ASGIApp:
    """The ASGI application uvicorn serves."""
    return build_gateway(upstream_url).http_app(transport="streamable-http")
