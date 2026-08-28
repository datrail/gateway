"""Receive an agent's MCP calls and forward them to the service behind us.

This is the transport half. It decides nothing yet — a ticket is read in a
later change, a policy bundle fetched in the one after — so every request that
arrives is forwarded.

Four choices here are not obvious, and each has a way of being wrong that
nothing would report:

  * **The backend is a `ProxyClient`, not a plain `Client`.** Only `ProxyClient`
    installs the handlers that relay a session's second channel — progress,
    log messages, sampling and elicitation. With a plain `Client` a long tool
    call still returns its result, so nothing looks broken, while every
    progress notification and log line it emitted was dropped on the way back
    and `ctx.sample()` fails outright. A component that claims to forward
    unchanged has to carry those too.

  * **The proxy is served directly, never mounted.** `FastMCP.mount` re-exposes
    an upstream's tools under a namespace when it is given one, and an
    endpoint key is `<datasource_slug>.<tool_name>`: a renamed tool matches no
    endpoint the control plane registered, while the agents were prompted with
    the real name. Serving directly is the shape that cannot acquire a prefix
    by someone later passing a namespace, rather than one that merely has none
    today.

  * **Incoming headers are not forwarded, and that line comes last.** Both
    `create_proxy` and `ProxyClient.__init__` set the flag True themselves, so
    an assignment before either is silently overwritten. Left on, a caller sets
    `x-rail` and it arrives upstream unchanged — the identity this component
    exists to check, supplied by the caller it exists to check. `authorization`
    rides the same path. fastmcp's own comment calls forwarding "only
    appropriate for proxy clients, where the caller's credentials should be
    propagated", which is the opposite of what an enforcement point needs.

  * **Enforcement belongs above the MCP layer, not inside it.** A refusal is an
    HTTP status: 403 for a call that was judged and denied, 503 for one that
    could not be judged at all. Inside an MCP server a refusal is a JSON-RPC
    error instead, which the control plane's denial contract does not describe
    and an operator cannot read off a status line.
"""

from __future__ import annotations

import logging
import os

from fastmcp import FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.server import create_proxy
from fastmcp.server.providers.proxy import ProxyClient
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
    """The port to listen on.

    Stripped before the default is applied, so a variable set to whitespace is
    read the same way `_required` reads one — as an operator who meant to set
    it — rather than reaching `int()` and reporting an empty value back.
    """
    raw = (os.environ.get("RAIL_GATEWAY_PORT") or "").strip() or str(DEFAULT_PORT)
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
    gateway = create_proxy(ProxyClient(transport), name="datrail-gateway")

    # Last, and it has to be: see the module docstring. Both `create_proxy` and
    # `ProxyClient.__init__` set this True, so an assignment above either one is
    # overwritten without a word. The two tests asserting nothing of the
    # caller's crosses are what make reordering these lines fail rather than
    # quietly reopen the hole.
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


def main() -> None:
    """Serve, on the configured port.

    The entry point exists so that `RAIL_GATEWAY_PORT` reaches the socket. A
    `CMD` naming the port on the uvicorn command line reads as equivalent and
    is not: the variable would be validated by `port()` and then ignored, so an
    operator who set it would get a gateway listening somewhere else and no
    error saying so.
    """
    import uvicorn

    # uvicorn configures its own loggers and leaves everything else to
    # `logging.lastResort`, which drops anything below WARNING — so without this
    # the only line stating where this gateway points is discarded.
    logging.basicConfig(
        level=os.environ.get("RAIL_GATEWAY_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    uvicorn.run(build_app(), host="0.0.0.0", port=port())


if __name__ == "__main__":
    main()
