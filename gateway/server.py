"""Receive an agent's MCP calls and forward them to the service behind us.

This is the transport half. It decides nothing yet — a ticket is read in a
later change, a policy bundle fetched in the one after — so every request that
arrives is forwarded.

Four choices here are not obvious, and each has a way of being wrong that
nothing would report:

  * **The backend is a `ProxyClient` with three of its five handlers refused.**
    Only `ProxyClient` relays a session's second channel; with a plain `Client`
    a long tool call still returns its result, so nothing looks broken, while
    every progress notification and log line it emitted is dropped on the way
    back.

    But its five defaults are not one thing. Progress and log messages travel
    *upstream to caller* and are what "forward unchanged" means. Roots,
    sampling and elicitation are requests travelling *upstream into the
    caller*: with them installed, the service behind this gateway can enumerate
    the caller's roots, drive the caller's model with a prompt of its choosing,
    and put a question of its own in front of the caller's human. That is a
    trust edge pointing the wrong way through an enforcement point, and it is
    not one the header boundary covers, so those three are passed `None`
    explicitly — `ProxyClient` installs a default only for a key absent from
    its kwargs.

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

    **This closes the header channel and not every channel.** A caller's
    `params._meta` on a `tools/call` is copied to the upstream verbatim, so a
    key named `x-rail` in there does cross. Nothing reads it — this component
    takes identity from the header alone, and so does the contract — but an
    upstream that invented its own convention could be fed by a caller, and the
    guarantee to state is "no caller header crosses", not "nothing does".

  * **Enforcement belongs above the MCP layer, not inside it.** A refusal is an
    HTTP status: 403 for a call that was judged and denied, 503 for one that
    could not be judged at all. Inside an MCP server a refusal is a JSON-RPC
    error instead, which the control plane's denial contract does not describe
    and an operator cannot read off a status line.
"""

from __future__ import annotations

import base64
import logging
import os
from urllib.parse import unquote, urlsplit, urlunsplit

from fastmcp import FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from fastmcp.server import create_proxy
from fastmcp.server.middleware import Middleware
from fastmcp.server.providers.proxy import ProxyClient
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

log = logging.getLogger("gateway")

DEFAULT_PORT = 8080

#: Checked against by name rather than through `logging.getLevelName`, whose
#: return type is the contract: an integer for a known name and the string
#: "Level <n>" for anything else, so a typo would set a level nobody chose.
LOG_LEVELS = frozenset({"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"})


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
    if not urlsplit(url).hostname:
        # `http://` and `http://user:pw@` both parse, and a gateway built on
        # either starts and answers /health while able to forward nothing.
        raise RuntimeError(
            f"RAIL_GATEWAY_UPSTREAM_URL names no host: {_safe_to_log(url)}"
        )

    clean_url, auth_headers = _split_credential(url)
    transport = StreamableHttpTransport(url=clean_url, headers=auth_headers)
    backend = ProxyClient(
        transport,
        # See the module docstring: relayed upstream-to-caller, refused
        # upstream-into-caller.
        roots=None,
        sampling_handler=None,
        elicitation_handler=None,
    )
    gateway = create_proxy(backend, name="datrail-gateway")
    gateway.add_middleware(_UpstreamErrorBoundary())

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

    log.info("forwarding to %s", _safe_to_log(url))
    return gateway


def build_app(upstream_url: str | None = None) -> ASGIApp:
    """The ASGI application uvicorn serves."""
    return build_gateway(upstream_url).http_app(transport="streamable-http")


def _split_credential(url: str) -> tuple[str, dict[str, str]]:
    """Move any `user:password@` out of the URL and into an Authorization header.

    Not cosmetic. httpx names the URL it called in its error text — `Client
    error '401 Unauthorized' for url '<url>'` — and fastmcp puts that string
    into the JSON-RPC error it returns to the caller. With the credential in
    the URL, an ordinary upstream 401 hands it to an unauthenticated agent, and
    a stale upstream key turns every call into a disclosure of it. The error
    boundary below cannot reach this one: the failure happens while the proxy
    is opening its session, before any message it wraps.

    The credential still travels, on the same request, in the header where a
    credential belongs.
    """
    parsed = urlsplit(url)
    if not parsed.username and not parsed.password:
        return url, {}
    credential = f"{unquote(parsed.username or '')}:{unquote(parsed.password or '')}"
    encoded = base64.b64encode(credential.encode()).decode()
    host = parsed.netloc.rsplit("@", 1)[-1]
    return (
        urlunsplit(parsed._replace(netloc=host)),
        {"Authorization": f"Basic {encoded}"},
    )


class _UpstreamErrorBoundary(Middleware):
    """Answer for the upstream rather than relaying what it said.

    httpx raises `Client error '401 Unauthorized' for url '<the upstream URL>'`,
    and fastmcp puts that string in the JSON-RPC error it returns — so an
    unauthenticated caller reading an ordinary failure is handed the upstream's
    address and, when the URL carries one, its credential. A stale upstream key
    turns every call into a disclosure of it.

    The detail is not lost; it goes to the log, which is on this side of the
    boundary. What crosses is that the upstream could not be reached.
    """

    async def on_message(self, context, call_next):
        try:
            return await call_next(context)
        except Exception as exc:  # noqa: BLE001 - a boundary catches everything
            log.warning("upstream call failed: %s: %s", type(exc).__name__, exc)
            raise ToolError("the upstream service could not be reached") from None


def _safe_to_log(url: str) -> str:
    """Where the gateway points, with every part that can carry a secret gone.

    `RAIL_GATEWAY_UPSTREAM_URL` can legitimately carry `user:password@`, and a
    hosted MCP endpoint commonly carries `?api_key=`. The line naming it is
    written on every start, so both would reach stdout and whatever collects it.

    Rebuilt rather than selectively rewritten. Clearing the authority alone left
    the query untouched; reassembling from `hostname` and `port` dropped the
    brackets an IPv6 literal needs and raised on a port that is not a number —
    a redaction helper crashing on the value it was handed being the worst
    shape available. Scheme, host and path are what an operator is reading for.
    """
    parsed = urlsplit(url)
    netloc = parsed.netloc.rsplit("@", 1)[-1]
    suffix = " (query omitted)" if parsed.query or parsed.fragment else ""
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", "")) + suffix


def _configure_logging() -> None:
    """Give this component's logger a handler, and nothing else one.

    uvicorn configures only `uvicorn*`, and `logging.lastResort` drops anything
    below WARNING — so without a handler here the line naming the upstream is
    discarded. `basicConfig` would do it by configuring the *root* logger, which
    also turns on INFO for httpx and every mcp module and buys around thirty
    lines per forwarded call.
    """
    raw = (os.environ.get("RAIL_GATEWAY_LOG_LEVEL") or "").strip() or "INFO"
    level = raw.upper()
    if level not in LOG_LEVELS:
        raise RuntimeError(
            f"RAIL_GATEWAY_LOG_LEVEL must be one of "
            f"{', '.join(sorted(LOG_LEVELS))}, got: {raw}"
        )
    log.setLevel(level)
    if log.handlers:
        # Called twice — by `main()` and by a test — this would otherwise add a
        # second handler and print every line twice.
        return
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    log.addHandler(handler)


def main() -> None:
    """Serve, on the configured port.

    The entry point exists so that `RAIL_GATEWAY_PORT` reaches the socket. A
    `CMD` naming the port on the uvicorn command line reads as equivalent and
    is not: the variable would be validated by `port()` and then ignored, so an
    operator who set it would get a gateway listening somewhere else and no
    error saying so.
    """
    import uvicorn

    _configure_logging()
    uvicorn.run(
        build_app(),
        host="0.0.0.0",
        port=port(),
        # A call in flight when SIGTERM lands otherwise gets no answer at all —
        # its response travels on a stream uvicorn's connection wait does not
        # cover, so the agent sees a hang rather than a failure. This bounds the
        # drain instead of skipping it.
        timeout_graceful_shutdown=25,
    )


if __name__ == "__main__":
    main()
