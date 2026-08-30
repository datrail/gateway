"""Receive an agent's MCP calls and forward them to the service behind us.

Every request is read, judged and **forwarded whatever the verdict**. The ticket
is decoded, the endpoint key composed, the held bundle walked, and the answer
written to the log — and then the call goes upstream exactly as it would have
without any of it. That is what `RAIL_TICKET_MODE=observe` means, and in this
build `enforce` behaves identically, because blocking is not implemented yet.

**Nothing here acts on a verdict, and that is the design of this change rather
than an omission.** A refusal wired in now would stop traffic for an enforcement
decision nothing downstream records: no denial is reported, no 403 or 503 is
specified until the change that adds them, so a request stopped here is a
request lost for nothing. What the verdict buys today is the log line an
operator runs a dry run for — which calls *would* stop, seen before enforcement
is turned on. The change that adds enforcement is the change that may act on it.

**`/ready` reports and does not gate**, on the same reasoning, and under
`RAIL_TICKET_MODE=none` it is unconditionally ready: a pass-through evaluates
nothing, needs no bundle to do its whole job, and must not be the deployment
that turns enforcement off and then never serves.

Seven choices here are not obvious, and each has a way of being wrong that
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

  * **The holder is built here and started by the lifespan.** Two different
    failures, kept apart on purpose. Everything the environment gets to say —
    the URL, the credential, the interval — is resolved while `build_gateway`
    runs, so a deployment configured wrongly is refused before a socket is
    open. Everything the network gets to say is resolved after, in the
    lifespan, where a control plane that is briefly down leaves a gateway that
    starts, serves, reports itself unready and keeps trying. Resolving the
    first lazily would turn a typo into a bundle that never arrives; resolving
    the second eagerly would turn a control-plane blip into a gateway that
    never comes up.

  * **`RAIL_TICKET_MODE=none` builds no holder at all**, rather than building
    one and declining to read it. The mode evaluates nothing, so a holder would
    poll Rail Center for the life of the process for a bundle nothing consults,
    and `RAIL_CENTER_URL` would be configuration a deployment must supply to a
    component that cannot use it. Both obligations the readiness change handed
    forward are discharged by that one absence: nothing polls, and `/ready`
    answers 200 because there is no holder to ask.

  * **The `/ready` route closes over the holder rather than reading it from the
    request.** A lifespan's yielded state does not reach `request.scope`
    through this stack — measured, not assumed: the dict comes back empty at
    the route. Closing over the object is also what keeps the answer live, so a
    bundle arriving after startup flips the report without anything having to
    notice and republish it.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from urllib.parse import unquote, urlsplit, urlunsplit

import httpx
from fastmcp import FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from fastmcp.server import create_proxy
from fastmcp.server.dependencies import get_http_request
from fastmcp.server.middleware import Middleware
from fastmcp.server.providers.proxy import ProxyClient
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

from gateway.auth import auth_headers
from gateway.bundle.client import BundleHolder, refresh_seconds
from gateway.bundle.conditions import ConditionInput, UninterpretableCondition
from gateway.bundle.decide import decide
from gateway.endpoint import resolve_endpoint_key
from gateway.key_safety import safe_for_log
from gateway.mode import TicketMode, describe, evaluates, ticket_mode
from gateway.ticket import parse_rail_header

log = logging.getLogger("gateway")

DEFAULT_PORT = 8080

#: How long the lifespan waits on the first policy bundle fetch before serving
#: anyway. Not the holder's deadline: this one is paid by `/health`, which
#: answers connection-refused until it elapses, so it is set against an
#: orchestrator's patience rather than against a control plane's.
STARTUP_FETCH_GRACE_SECONDS = 5.0

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


def _checked_url(name: str, url: str) -> str:
    """`url`, once it is one that names somewhere to go.

    Both variables this validates are addresses the process cannot function
    without and cannot discover to be wrong: `http://` and `http://user:pw@`
    parse, and a gateway built on either starts and answers `/health` while
    reaching nothing. The upstream one forwards nothing; the Rail Center one
    fetches no bundle ever, and reports it in the log as a control plane that
    is down — a fault an operator would look for in the wrong place entirely.
    """
    try:
        hostname = urlsplit(url).hostname
    except ValueError as exc:
        # An unclosed IPv6 bracket raises here, before the host check below —
        # a bare traceback that never names the variable the operator set.
        # Through `_credential_free` and not `_safe_to_log`: the message being
        # reported is the one `urlsplit` raised, so anything that parses to
        # redact would raise it again.
        raise RuntimeError(
            f"{name} is not a URL that can be parsed: {_credential_free(str(exc), url)}"
        ) from None
    if not hostname:
        raise RuntimeError(f"{name} names no host: {_safe_to_log(url)}")
    return url


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


def _holder_from_environment() -> BundleHolder:
    """The policy bundle holder a deployment's variables describe.

    Every one of them is read here rather than inside the holder, so the whole
    of what an operator can misconfigure is refused in one place at startup:
    `auth_headers` raises on a credential that cannot go in a header, and
    `refresh_seconds` on an interval that is not a number.

    `RAIL_CENTER_URL` goes through `_split_credential` for the same reason the
    upstream URL does and one more: httpx derives `BasicAuth` from a URL's
    userinfo and **overwrites** the `Authorization` header it was given, so a
    `user:password@` left in this one silently displaces the configured bearer
    token and calls the control plane as somebody else. Two credentials is an
    operator who set both by accident, and `auth.py` is explicit that a gateway
    which cannot send the credential it was configured for stops rather than
    sends a different one.
    """
    url, from_url = _split_credential(
        _checked_url("RAIL_CENTER_URL", _required("RAIL_CENTER_URL"))
    )
    configured = auth_headers()
    if from_url and "Authorization" in configured:
        raise RuntimeError(
            "RAIL_CENTER_URL carries a credential and RAIL_AUTH_MODE configures "
            "one; only one of them can be sent, so set exactly one"
        )
    return BundleHolder(
        url,
        {**from_url, **configured},
        interval_seconds=refresh_seconds(),
    )


def datasource_slug() -> str:
    """`RAIL_DATASOURCE_SLUG` — the first segment of every endpoint key.

    Read only where the gateway evaluates. It plays no part in fetching: the
    bundle route takes no parameters and is single-tenant per deployment, so
    this names the data source whose endpoints the bundle's bindings are keyed
    on, and nothing else. A deployment that got it wrong composes keys matching
    no binding, and every endpoint falls back to the whole chain — which denies
    more than the operator wrote rather than less, but is still not what they
    wrote.
    """
    return _required("RAIL_DATASOURCE_SLUG")


def build_gateway(
    upstream_url: str | None = None,
    holder: BundleHolder | None = None,
    mode: TicketMode | None = None,
    slug: str | None = None,
) -> FastMCP:
    """The proxy that forwards to the upstream, plus liveness and readiness.

    `holder`, `mode` and `slug` are injected by the suite so its gateways answer
    to a control plane the test holds, in a mode the test chose, fronting a data
    source the test named. A caller that passes none of them gets what the
    environment describes.

    **Under `RAIL_TICKET_MODE=none` no holder is built at all**, whether or not
    one was passed, and `RAIL_CENTER_URL` is not read. A pass-through evaluates
    nothing, so polling Rail Center on a timer for a bundle it will never read
    would be load on the control plane bought for nothing — and requiring the
    variable would be configuration a deployment must supply to a component that
    cannot use it. An injected holder is ignored rather than honoured because
    the mode is the stronger statement: a test asking for `none` is asking for a
    gateway that does not fetch.
    """
    resolved_mode = mode if mode is not None else ticket_mode()
    url = _checked_url(
        "RAIL_GATEWAY_UPSTREAM_URL",
        upstream_url or _required("RAIL_GATEWAY_UPSTREAM_URL"),
    )
    # After the upstream, so a gateway pointed nowhere is refused for that
    # rather than for the Rail Center variable it also has not been given.
    if not evaluates(resolved_mode):
        bundle_holder = None
        endpoint_slug = None
    else:
        bundle_holder = holder if holder is not None else _holder_from_environment()
        endpoint_slug = slug if slug is not None else datasource_slug()
    log.info("%s", describe(resolved_mode))

    clean_url, credential_headers = _split_credential(url)
    transport = StreamableHttpTransport(url=clean_url, headers=credential_headers)
    backend = ProxyClient(
        transport,
        # See the module docstring: relayed upstream-to-caller, refused
        # upstream-into-caller.
        roots=None,
        sampling_handler=None,
        elicitation_handler=None,
    )
    gateway = create_proxy(
        backend,
        name="datrail-gateway",
        lifespan=_bundle_lifespan(bundle_holder),
    )
    gateway.add_middleware(_UpstreamErrorBoundary())
    if bundle_holder is not None and endpoint_slug is not None:
        gateway.add_middleware(_PolicyVerdict(bundle_holder, endpoint_slug))

    # Last, and it has to be: see the module docstring. Both `create_proxy` and
    # `ProxyClient.__init__` set this True, so an assignment above either one is
    # overwritten without a word. The two tests asserting nothing of the
    # caller's crosses are what make reordering these lines fail rather than
    # quietly reopen the hole.
    transport.forward_incoming_headers = False

    @gateway.custom_route("/health", methods=["GET"])
    async def health(_request):  # pragma: no cover - exercised over HTTP
        """Liveness only: the process is up and its configuration parsed.

        It says nothing about the policy bundle, and must not learn to. The two
        questions have opposite remedies — a process that is not live should be
        replaced, a process that is not ready should be left alone to become
        ready — so an orchestrator handed one answer for both restarts a
        gateway whose only problem is a control plane it cannot reach yet, and
        restarting is the one action that cannot help.
        """
        return JSONResponse({"status": "ok"})

    @gateway.custom_route("/ready", methods=["GET"])
    async def ready(_request):  # pragma: no cover - exercised over HTTP
        """Whether a policy bundle is held. Asked fresh, answered honestly.

        `None` from `current()` is *no ruleset*, never *an empty one* — an
        empty chain allows — so the only thing this can truthfully report while
        nothing is held is that this gateway would have nothing to decide with.
        503 rather than a 200 carrying a false flag, because the code is the
        part every orchestrator and load balancer reads without being taught to.

        **Under `RAIL_TICKET_MODE=none` it is unconditionally ready.** A
        pass-through evaluates nothing, so it needs no bundle to do its whole
        job, and reporting it unready would leave the deployment that turns
        enforcement off as the one that never serves — a switch whose off
        position takes the component down is not an off position.

        **What it deliberately does not carry is the version held.** This route
        is unauthenticated and shares a port with the MCP surface, so a version
        here is a public feed of when a customer's policy changed, bought for an
        operator convenience the `holding policy bundle version …` log line
        already covers.
        """
        if bundle_holder is None:
            return JSONResponse({"status": "ready"})
        if bundle_holder.current() is None:
            return JSONResponse({"status": "not ready"}, status_code=503)
        return JSONResponse({"status": "ready"})

    log.info("forwarding to %s", _safe_to_log(url))
    return gateway


def _bundle_lifespan(holder: BundleHolder | None):
    """Start the holder with the application and stop it with the application.

    `holder` is None under `RAIL_TICKET_MODE=none`, where there is nothing to
    start: the mode evaluates no policy, so a lifespan that fetched one anyway
    would poll Rail Center for the whole life of a process that will never read
    the answer.

    **Nothing here catches.** `start()` turns every expected failure — an
    unreachable control plane, a refused credential, a bundle that will not
    validate — into an outcome it returns, so anything that raises past it is a
    defect rather than a deployment's circumstances. A process that fails to
    start names that defect; one that logged it and carried on would be a
    gateway serving traffic, reporting itself unready for ever, and never
    retrying — because the refresh loop is created after the first fetch and a
    raise means it never was.

    **The first fetch is awaited, and only for `STARTUP_FETCH_GRACE_SECONDS`.**
    Waiting for it is what makes `/ready` answerable from the first request
    rather than briefly reporting a state no attempt has established yet, and
    what puts the line below in the log before the process claims to be up. But
    uvicorn binds no socket until this function reaches its `yield`, so every
    second spent here is a second `/health` answers *connection refused* rather
    than 503 — which is the one shape of failure liveness must never take, since
    an orchestrator reads it as a process to replace and restarting cannot help
    a control plane that is merely slow. Unbounded, that wait runs to the
    holder's own deadline, which is long enough for a default Kubernetes
    liveness probe to kill the container and long enough for the next start to
    repeat it. So the fetch runs as a task, the wait on it is short, and a fetch
    still running when the grace expires is left to finish in the background —
    where the refresh loop it creates picks up exactly as it would have.
    """

    @asynccontextmanager
    async def lifespan(_server) -> AsyncIterator[None]:
        if holder is None:
            # `RAIL_TICKET_MODE=none`. Nothing to start, nothing to stop, and
            # the app serves immediately — there is no first fetch to wait on.
            yield
            return
        # `asyncio.wait` rather than `wait_for`: a timeout there cancels what it
        # was waiting on, and cancelling this one would take the refresh loop
        # with it — `start()` creates the loop after the first fetch returns.
        first = asyncio.create_task(holder.start())
        done, _ = await asyncio.wait({first}, timeout=STARTUP_FETCH_GRACE_SECONDS)
        if first in done:
            # `.result()` and not a `try`: **nothing here catches**, per above.
            outcome = first.result()
            if outcome.held is None:
                # Not fatal, and worth a line at this level: it is the whole
                # difference between a gateway that is starting and one that is
                # stuck, and `/ready` reports only the bit.
                log.warning(
                    "started holding no policy bundle: %s — /ready reports not ready "
                    "until one arrives",
                    outcome.reason or outcome.kind,
                )
        else:
            log.warning(
                "started holding no policy bundle: the first fetch has run for "
                "%ss and is still going — /ready reports not ready until one "
                "arrives",
                STARTUP_FETCH_GRACE_SECONDS,
            )
        try:
            yield
        finally:
            # In a `finally` so a failure anywhere in the served life of the
            # app still retires the refresh loop. Left running, it holds the
            # event loop open and uvicorn's shutdown waits on it.
            #
            # `stop()` first: it retires the epoch a first fetch still in flight
            # captured, so that fetch returns without creating a loop nothing
            # would then hold a handle to.
            await holder.stop()
            first.cancel()
            try:
                await first
            except asyncio.CancelledError:
                pass
            except Exception:
                # Only reachable past the grace, where the raise this function
                # does not catch can no longer refuse the start. It is still a
                # defect, so it is still said out loud.
                log.exception("the first policy bundle fetch raised")

    return lifespan


def build_app(
    upstream_url: str | None = None,
    holder: BundleHolder | None = None,
    mode: TicketMode | None = None,
    slug: str | None = None,
) -> ASGIApp:
    """The ASGI application uvicorn serves."""
    return build_gateway(upstream_url, holder, mode, slug).http_app(
        transport="streamable-http"
    )


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


class _PolicyVerdict(Middleware):
    """Evaluate every call against the held bundle, and act on none of it.

    **This is the whole of what `observe` means, and today `enforce` behaves the
    same way** — blocking arrives in the change that adds it. Wiring a refusal
    here now would be an outage bought for no enforcement: nothing downstream
    reads a verdict, so a request stopped is a request lost for nothing.

    What it produces is the log line an operator runs a dry run for. A verdict
    computed and written down is what tells them which calls *would* stop before
    they turn enforcement on, and it is the only thing this branch owes them.

    Three failures are answered here rather than left to propagate, because a
    gateway that forwards nothing is worse than one that enforces nothing:

      * **No bundle held.** The contract's answer is to refuse, and refusing is
        exactly what this branch does not do yet — so the call is forwarded and
        the line says the request went unjudged. That is the honest report:
        `/ready` already says the gateway holds nothing, and inventing a verdict
        from an absent ruleset would be worse than saying there was none.
      * **A condition outside the grammar.** `decide` raises where the walk
        reaches it. Under enforcement that is a 503 and no denial report;
        here it is logged at error level naming the offending policy, because
        that line is the signal that Rail Center and this gateway have drifted,
        which is the actual fault and the only thing that fixes it.
      * **Anything else.** A defect in the walk must not take the forward path
        down while the walk decides nothing. It is logged with a traceback and
        the call proceeds — the one place in this file that catches broadly, and
        it is defensible only because the verdict is inert.
    """

    def __init__(self, holder: BundleHolder, slug: str) -> None:
        self._holder = holder
        self._slug = slug

    async def on_message(self, context, call_next):
        self._record(context)
        return await call_next(context)

    def _record(self, context) -> None:
        """Write down what the walk concluded. Never raises."""
        resolution = resolve_endpoint_key(
            getattr(context, "method", None),
            getattr(getattr(context, "message", None), "name", None),
            self._slug,
        )
        bundle = self._holder.current()
        if bundle is None:
            log.warning(
                "no policy bundle held — forwarding %s unjudged",
                safe_for_log(resolution.key or resolution.status),
            )
            return

        request = ConditionInput(
            ticket=parse_rail_header(_x_rail_header()),
            endpoint_key=resolution.key,
        )
        try:
            verdict = decide(bundle, request)
        except UninterpretableCondition as refusal:
            log.error(
                "refusing to judge %s — %s; Rail Center and this gateway have "
                "drifted, and the request was forwarded because this build "
                "enforces nothing",
                safe_for_log(resolution.key or resolution.status),
                refusal.reason,
            )
            return
        except Exception:
            log.exception(
                "policy evaluation raised for %s; the request was forwarded",
                safe_for_log(resolution.key or resolution.status),
            )
            return

        for alert in verdict.alerts:
            log.warning(
                "policy %s alerts on %s",
                safe_for_log(alert.id),
                safe_for_log(resolution.key or resolution.status),
            )
        if verdict.allowed:
            log.info(
                "allow %s (ticket %s)",
                safe_for_log(resolution.key or resolution.status),
                request.ticket.state,
            )
            return
        # The policy that *actually matched*, never the first in the chain: this
        # id is what a denial report will name once one is sent, and an operator
        # reading a rule that did not decide has no second opinion to correct it.
        log.warning(
            "would deny %s by policy %s (ticket %s) — this build enforces "
            "nothing, so the request was forwarded",
            safe_for_log(resolution.key or resolution.status),
            safe_for_log(verdict.denied_by.id if verdict.denied_by else None),
            request.ticket.state,
        )


def _x_rail_header() -> list[str] | None:
    """Every `x-rail` value on the request, or None when there is no request.

    **`getlist`, and it has to be.** The contract refuses a repeated `x-rail`
    outright and says why the check cannot be deferred: by the time a platform
    has collapsed two values into one the evidence is gone. Both of the obvious
    routes here lose it — `get_http_headers()` returns a `dict[str, str]`, and
    Starlette's `Headers.get` returns the *first* value, which decodes normally.
    Either would admit a ticket an attacker chose by sending the header twice,
    while Node's header handling joins the pair into `"AAA, BBB"` and refuses
    it. That is two conformant-looking implementations reaching opposite
    verdicts on input the caller fully controls.

    `parse_rail_header` takes the list and classifies a repeat as
    `undecodable`, so the whole of this function's job is not to flatten it.

    A message with no HTTP request behind it — an in-process transport, a test —
    has no header to read, and no ticket is exactly what `absent` means.
    """
    try:
        request = get_http_request()
    except RuntimeError:
        # Documented: "No active HTTP request found." Narrow on purpose — a
        # blind except here would swallow a defect in the accessor and report
        # it as an absent ticket, which denies rather than admits but hides the
        # fault either way.
        return None
    # `[]` for a header that was never sent, which `parse_rail_header` reads as
    # absent exactly as it reads None.
    return request.headers.getlist("x-rail") or None


class _UpstreamErrorBoundary(Middleware):
    """Answer for the upstream rather than relaying what it said.

    An upstream that fails *mid-session* raises through here, and its error text
    names the URL it called — so without this the caller reads the upstream's
    address off an ordinary failure. The detail is not lost; it goes to the log,
    which is on this side of the boundary.

    **It does not cover the session opening.** fastmcp turns a connection-setup
    failure into a JSON-RPC error it returns rather than one it raises, so
    nothing passes through here and the caller does see that text. Keeping the
    credential out of the URL (`_split_credential`) is what limits what such a
    message can say.
    """

    async def on_message(self, context, call_next):
        try:
            return await call_next(context)
        except (httpx.HTTPError, ConnectionError, OSError) as exc:
            # Transport failures only. Catching everything turned `Unknown
            # tool: 'no_such_tol'` into "the upstream service could not be
            # reached", so a caller's typo read as an outage and the real
            # answer never arrived.
            log.warning("upstream call failed: %s: %s", type(exc).__name__, exc)
            raise ToolError("the upstream service could not be reached") from None


def _credential_free(text: str, url: str) -> str:
    """`text`, with any credential `url` carries taken back out of it.

    The redaction every message about a rejected URL is built on. `urlsplit`
    raises `ValueError("netloc '<netloc>' contains invalid characters under
    NFKC normalization")` for a host that normalises into a delimiter, and it
    quotes that netloc **whole, userinfo included** — so interpolating the
    exception into a startup error writes a live control-plane password to
    stderr, where the container's log collector and the CI log of every job
    that runs the image both keep it. Parsing is no help on that path: it is
    the branch reached because parsing raised. So the authority is found by
    string surgery on the raw value instead, and whatever precedes its last
    `@` is removed wherever the message repeats it.

    Removed together with that `@`, and replaced by a marker that keeps one.
    The userinfo on its own is a short, ordinary string — `svc`, `api` — and
    replacing every occurrence of it overwrote the host and the path as well:
    `https://svc@svc.default.svc.cluster.local:8080/mcp` came out as
    `https://***.default.***.cluster.local:8080/mcp`, losing the half of the
    line an operator reads it for. A credential is only a credential where it
    sits in front of an `@`, so that is what is matched.

    An authority does not need `scheme://` in front of it, and keying off that
    separator finds nothing in exactly the malformed values these messages are
    written for: `//user:pw@host/`, and the `user:pw@host/` of an operator who
    forgot the scheme, both carry one.
    """
    _, separator, rest = url.partition("://")
    authority = rest if separator else url.removeprefix("//")
    for delimiter in "/?#":
        authority = authority.partition(delimiter)[0]
    userinfo = authority.rpartition("@")[0]
    return text.replace(f"{userinfo}@", "***@") if userinfo else text


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

    The credential comes out through `_credential_free` first, on the raw
    string, because the rebuild below only redacts a URL that has an authority
    to rebuild and `scheme://` is what tells `urlsplit` there is one. This is
    also called on the value `_checked_url` rejects for naming no host, and
    `user:pw@host/` — an operator who forgot the scheme — parses as a scheme
    with the rest as path: an empty netloc, from which the rebuild strips
    nothing and returns the password whole.
    """
    parsed = urlsplit(_credential_free(url, url))
    netloc = parsed.netloc.rsplit("@", 1)[-1]
    dropped = [
        n for n, v in (("query", parsed.query), ("fragment", parsed.fragment)) if v
    ]
    suffix = f" ({' and '.join(dropped)} omitted)" if dropped else ""
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
    # No `timeout_graceful_shutdown`: it was tried and does not do the job.
    # A tool call's answer travels on a streamable-http stream that uvicorn's
    # connection wait does not cover, so SIGTERM abandons a call in flight
    # whatever the timeout says — measured, the process exits in under a second
    # and the caller hangs to its own limit with no response. A value longer
    # than `docker stop`'s ten seconds would be SIGKILLed before it helped.
    # Draining this properly needs the ASGI app to hold the shutdown until its
    # streams finish, which this change does not build.
    uvicorn.run(build_app(), host="0.0.0.0", port=port())


if __name__ == "__main__":
    main()
