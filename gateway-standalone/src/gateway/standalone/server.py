"""Receive an agent's MCP calls and forward them to the service behind us.

Every request is read and judged: the ticket is decoded, the endpoint key
composed, the held bundle walked, and the answer written to the log. What
happens next is the **bundle's** to say, not this deployment's (RC-312): it
carries `enforcement`, and an operator moving a gateway between postures is a
poll rather than a redeploy. Under `observe` the call goes upstream exactly as
it would have without any of it. Under `enforce` a verdict is acted on — a
denied call is answered 403 and reported to Rail Center, and one that could not
be judged at all is answered 503 and reported to nobody. Under `none` there is
no walk to act on.

**`enforce` also refuses what it was never given a rule about**, where the
bundle's `fallback` says `block`: an endpoint carrying no binding entry is
answered 403 before the chain is consulted. The caller is told what every denied
caller is told, and Rail Center is told nothing, because no policy decided it
and a report names the policy that matched.

**403 and 503 are kept apart deliberately.** A 403 says the call was judged and
rejected; a 503 says the ruleset could not be applied at all. Only the first
names a policy that decided anything, so only the first is reported — naming a
policy on the second would attribute a verdict nobody reached.

**Only `enforce` reports.** `observe` runs the same walk, logs the same verdict,
forwards the request, never consults the fallback, and sends nothing — a denial
table filled from a mode that is explicitly not enforcing leaves an operator
unable to tell which rows stopped traffic.

**`/ready` reports and does not gate**, and with the plugin disabled it is
unconditionally ready: a pass-through evaluates nothing, needs no bundle to do
its whole job, and must not be the deployment that turns enforcement off and
then never serves.

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

  * **Each proxy is served directly, never mounted.** `FastMCP.mount` re-exposes
    an upstream's tools under a namespace when it is given one, and an endpoint
    key is `<path>#<method>#<call>`: a renamed tool matches no endpoint the
    control plane registered, while the agents were prompted with the real name.
    Several upstreams are told apart by the prefix they arrive under — see
    `_Routed` — which leaves the message itself untouched, where a namespace
    would rewrite the one field the key is composed from. Serving directly is
    the shape that cannot acquire a namespace by someone later passing one,
    rather than one that merely has none today.

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

  * **`RAIL_PLUGIN_ENABLED=false` builds no holder at all**, rather than building
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

import asyncio
import logging
from collections.abc import AsyncIterator, Sequence
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Any, Final
from urllib.parse import quote, unquote

import httpx
from fastmcp import FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from fastmcp.server import create_proxy
from fastmcp.server.middleware import Middleware
from fastmcp.server.providers.proxy import ProxyClient
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

from gateway.core.bundle.client import BundleHolder
from gateway.core.enforcement import DenialReporter, judge, refusal_body
from gateway.core.key_safety import safe_for_log
from gateway.core.logs import configure_logging
from gateway.core.mode import describe_plugin, plugin_enabled
from gateway.core.settings import (
    _checked_url,
    _safe_to_log,
    _split_credential,
    build_holder,
    port,
    rail_center_from_environment,
)
from gateway.standalone.routes import Route, load_routes

log = logging.getLogger(__name__)

#: How long the lifespan waits on the first policy bundle fetch before serving
#: anyway. Not the holder's deadline: this one is paid by `/health`, which
#: answers connection-refused until it elapses, so it is set against an
#: orchestrator's patience rather than against a control plane's.
STARTUP_FETCH_GRACE_SECONDS = 5.0


def build_gateway(
    route: Route,
    holder: BundleHolder | None = None,
    plugin: bool | None = None,
    *,
    polls: bool = True,
) -> FastMCP:
    """The proxy that forwards to the upstream, plus liveness and readiness.

    `holder` and `plugin` are injected by the suite so its gateways answer to a
    control plane the test holds. The endpoint slug is not needed here:
    composing keys is the enforcement layer's, and this builds the MCP server
    that sits under it.

    **Under `RAIL_PLUGIN_ENABLED=true` a holder is always built, whatever posture
    the bundle turns out to carry** (RC-312). That is the inversion, and it
    reads backwards until you ask what the alternative costs: a component that
    declined to poll while its posture was `none` could never be told the
    posture had moved, so an operator who disabled enforcement during an
    incident would need a redeploy to undo it. Polling is what makes the switch
    turn both ways, and the bundle it polls for is cheap.

    **With the plugin off no holder is built at all**, whether or not one was
    passed, and `RAIL_CENTER_URL` is not read. The flag means *RailXia is not
    installed here* rather than *do not enforce*, so there is nothing to poll and
    requiring the variable would be configuration a deployment must supply to a
    component with nothing to point it at. An injected holder is ignored rather
    than honoured because the flag is the stronger statement: a test asking for
    the plugin off is asking for a gateway with no control plane.

    **`polls=False` starts no poll loop. It does not decide which holder is
    read.** A gateway fronting several upstreams polls on one proxy and hands
    the same holder to the rest, so there is one poll loop against a control
    plane with one bundle to give and every route's `/ready` answers off that
    one bundle. Readiness is the gateway's state rather than a route's: the
    enforcement layer on every route reads this same holder, so a route
    answering ready off a holder of its own would tell a probe that a route
    forwarding every call unjudged is ready to serve.

    **A non-polling proxy handed no holder resolves none from the environment**,
    which is what keeps `polls=False` from meaning `None`. `None` on its own is
    *nobody handed one down, so resolve one*; resolving one here would be a
    holder nothing ever starts, and a holder nothing starts holds nothing for
    the life of the process.
    """
    resolved_plugin = plugin if plugin is not None else plugin_enabled()
    url = _checked_url(f"the url for upstream '{route.name}'", route.url)
    # After the upstream, so a gateway pointed nowhere is refused for that
    # rather than for the Rail Center variable it also has not been given.
    if not resolved_plugin:
        bundle_holder = None
    elif not polls:
        bundle_holder = holder
    else:
        bundle_holder = holder if holder is not None else build_holder()
    log.info("%s", describe_plugin(resolved_plugin))

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
        # Read by `/ready` whether or not this proxy polls; started only where
        # it does, since the loop is what `polls` decides.
        lifespan=_bundle_lifespan(bundle_holder if polls else None),
    )
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

        **With the plugin disabled it is unconditionally ready**, and after
        RC-312 that is a statement about enrolment rather than about posture. A
        component with no control plane has no bundle to wait for and never will
        have, so waiting would leave it permanently unready.

        **Under `plugin` it is 503 until a bundle arrives, at every posture.**
        Not only the ones that act: a gateway holding a bundle has a ruleset to
        decide with whatever posture that bundle names, while a gateway holding
        nothing has none, and those are different states even though both
        forward every request. This route is the one place the difference is
        visible to an orchestrator, which is what makes it worth 503 on a gateway
        that is, for the moment, behaving exactly like a ready one.

        **What it does not separate is whether a posture was stated.** A bundle
        naming no `enforcement` is held like any other, so this answers 200 for
        it exactly as it does for a bundle saying `none` — one has been told
        nothing and the other was told to judge nothing, and both have something
        to decide with. What tells them apart is the posture line a poll logs,
        not this status code.

        It re-keys on the same expression it always did — the holder's absence —
        because that absence now means *not enrolled* rather than *does not
        enforce*. What changed is what the words mean, not what the code asks.

        **What it deliberately does not carry is the content hash held.** This
        route is unauthenticated and shares a port with the MCP surface, so a
        hash here is a public feed of when a customer's policy changed, bought
        for an operator convenience the `holding policy bundle …` log line
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

    `holder` is None where the plugin is disabled and where this proxy is not
    the one that polls, and neither has anything to start. A disabled plugin
    evaluates no policy, so a lifespan that fetched one anyway would poll Rail
    Center for the whole life of a process that will never read the answer; a
    non-polling proxy reads a holder another proxy in the same process fills,
    and starting it again would be a second loop for one bundle.

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
            # the plugin disabled, or a proxy that does not poll. Nothing to
            # start, nothing to stop, and the app serves immediately — there is
            # no first fetch to wait on.
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
    routes: list[Route] | None = None,
    holder: BundleHolder | None = None,
    plugin: bool | None = None,
    *,
    rail_center: tuple[str, dict[str, str]] | None = None,
    report_transport: httpx.AsyncBaseTransport | None = None,
) -> ASGIApp:
    """The ASGI application uvicorn serves.

    The configuration is resolved **here** and handed down, rather than each
    layer reading the environment for itself: the holder and the denial reporter
    both reach Rail Center, and a gateway fetching policy as one identity while
    reporting denials as another is a state nothing would report.

    `_Enforcement` wraps the MCP application rather than sitting inside it, for
    the reason its own docstring gives. With the plugin disabled there is
    nothing to wrap it with — no control plane, no holder, no slug, no walk —
    and the app is served bare.

    **Under `plugin` it is always wrapped, at every posture** (RC-312). What the
    wrapper does with a call is read from the held bundle per request rather
    than decided here, because the posture arrives on a poll and may change
    between two of them; a wrapper installed only for the postures that act
    would have to be installed or removed while the process runs, which is not a
    thing an ASGI stack can do.
    """
    resolved_plugin = plugin if plugin is not None else plugin_enabled()
    resolved_routes = routes if routes is not None else load_routes()

    if not resolved_plugin:
        bare = [
            (
                route,
                build_gateway(route, None, resolved_plugin).http_app(
                    transport="streamable-http"
                ),
            )
            for route in resolved_routes
        ]
        return _Routed(bare, bare[0][1], [app for _, app in bare[1:]])

    resolved_holder = holder if holder is not None else build_holder()
    url, auth = (
        rail_center if rail_center is not None else rail_center_from_environment()
    )

    # **The holder is the gateway's, not a route's**: every proxy is built with
    # it and exactly one polls it. The poll is started by a lifespan, so polling
    # on each of them would run one loop per upstream against a control plane
    # that has one bundle to give — while a route built without the holder would
    # answer `/ready` off nothing and report itself ready while every call
    # through it went unjudged. The polling proxy is also the one answering
    # `/health` and `/ready` at the root, which is why `_Routed` keeps a
    # reference to it.
    mounted: list[tuple[Route, ASGIApp]] = []
    primary: ASGIApp | None = None
    secondaries: list[Starlette] = []
    for route in resolved_routes:
        polls = primary is None
        gateway = build_gateway(
            route,
            resolved_holder,
            resolved_plugin,
            polls=polls,
        )
        served = gateway.http_app(transport="streamable-http")
        app = _Enforcement(
            served,
            resolved_holder,
            rail_center_url=url,
            auth=auth,
            transport=report_transport,
        )
        if polls:
            primary = app
        else:
            # Enforcement still reads the gateway's one holder; what this route
            # does without is the poll loop that fills it.
            secondaries.append(served)
        mounted.append((route, app))
    assert primary is not None  # `load_routes` refuses a file naming none
    return _Routed(mounted, primary, secondaries)


class _Routed:
    """Dispatch a request to the upstream whose prefix it arrived under.

    **The prefix is the only thing that decides routing.** An MCP `tools/call`
    names a tool and nothing else, so two upstreams reachable at one address are
    indistinguishable in the message — which is why the agent-facing URL becomes
    per-upstream and why `gateway.standalone.routes` refuses overlapping prefixes at
    startup. A request matching two routes has no answer this gateway could
    give, and one matching none is a 404 rather than a guess.

    **The prefix is removed before the sub-app sees the request**, so the path it
    receives — and the path an endpoint key is composed from — is the one the
    upstream serves. It travels on to that sub-app as `X-Forwarded-Prefix`,
    Traefik's convention rather than one invented here, for a framework beneath
    this layer that builds absolute URLs. It travels no further: the proxy
    reaches the upstream as an MCP client over a transport that forwards none of
    the incoming headers, so the header is the gateway's own to read.

    **The gateway's own `/health` and `/ready` are the ones at the root**, and
    they are answered off the primary sub-app — the one holding the bundle.
    Beneath a prefix the same two paths reach that route's own proxy and
    describe that proxy, which is the sub-app's answer to give rather than this
    layer's to intercept.

    **Every sub-app is started, not only the one that serves the lifespan
    scope.** Each carries its own `StreamableHTTPSessionManager`, and one whose
    task group was never entered answers 500 to every request that reaches it —
    so an upstream that is mounted but unstarted is a route the gateway cannot
    serve at all.
    """

    #: Answered at the root, by the gateway rather than by a route.
    META_PATHS: Final[frozenset[str]] = frozenset({"/health", "/ready"})

    def __init__(
        self,
        mounted: list[tuple[Route, ASGIApp]],
        primary: ASGIApp,
        secondaries: Sequence[Starlette] = (),
    ) -> None:
        # Longest first, so the match is deterministic whatever order the file
        # listed them in. Overlaps are already refused, so this orders rather
        # than resolves — but a reader should not have to know that to see that
        # two prefixes cannot both match.
        self._mounted = sorted(
            mounted, key=lambda pair: len(pair[0].strips), reverse=True
        )
        self._primary = primary
        #: The sub-apps `primary` does not start: every mounted app but its own.
        #: Held as the Starlette instances rather than as what `_mounted` serves,
        #: because the lifespan is the router's and an enforcement wrapper has
        #: none of its own.
        self._secondaries = list(secondaries)

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "lifespan":
            # The scope is served by `primary`, which runs the startup and
            # shutdown messaging the server is waiting on. The others are
            # entered around it — a lifespan scope forwarded to more than one
            # app would have each of them answer `lifespan.startup.complete` on
            # the one channel — and unwound when it returns.
            async with AsyncExitStack() as stack:
                for app in self._secondaries:
                    await stack.enter_async_context(app.router.lifespan_context(app))
                await self._primary(scope, receive, send)
            return
        path = scope.get("path") or ""
        if path in self.META_PATHS:
            await self._primary(scope, receive, send)
            return
        for route, app in self._mounted:
            rest = _beneath(path, route.strips)
            if rest is None:
                continue
            await app(_under_prefix(scope, route, rest), receive, send)
            return
        await _refuse(send, 404, f"no upstream is mounted at {safe_for_log(path)}")


def _beneath(path: str, prefix: str) -> str | None:
    """`path` with `prefix` removed, or None where it is not beneath it.

    The root prefix strips nothing and matches everything, which is the
    single-upstream deployment. Otherwise the match is on a path boundary: `/d`
    claims `/d` and `/d/mcp`, and never `/d-eu/mcp`.
    """
    if not prefix:
        return path
    if path == prefix:
        return "/"
    if path.startswith(prefix + "/"):
        return path[len(prefix) :]
    return None


def _under_prefix(scope, route: Route, rest: str):
    """`scope`, rewritten as the sub-app and the upstream should see it.

    `raw_path` is rewritten beside `path` because the two describe one request,
    and a stale one hands the sub-app the string this layer just removed.

    **`path` carries the strip and `root_path` is left as it was found.** Only
    one of them may: Starlette routes on `get_route_path`, which removes
    `root_path` from `path` itself, so a prefix in both is removed twice. With
    the prefix in `root_path` as well, an upstream mounted at `prefix: /mcp`
    would be routed the empty path and serve nothing, and `/a/a/mcp` would be
    served as `/a/mcp` under a key naming an endpoint nobody serves. The prefix
    reaches the sub-app as `X-Forwarded-Prefix`, for a framework beneath this
    layer that builds absolute URLs, and reaches nothing past it: the proxy
    forwards none of its incoming headers to the upstream.
    """
    headers = [
        (name, value)
        for name, value in scope.get("headers", [])
        if name != b"x-forwarded-prefix"
    ]
    if route.strips:
        # Percent-encoded, because a header value is bytes and a prefix is a
        # path: `/路径` has no latin-1 spelling to send, and an ASCII prefix —
        # every one in practice — is unchanged by this.
        headers.append((b"x-forwarded-prefix", quote(route.strips).encode("ascii")))
    rewritten = dict(scope)
    rewritten["path"] = rest
    rewritten["headers"] = headers
    raw_path = scope.get("raw_path")
    if raw_path is not None:
        rewritten["raw_path"] = _raw_beneath(raw_path, route.strips)
    return rewritten


def _raw_beneath(raw: bytes, prefix: str) -> bytes:
    """`raw` with the bytes spelling `prefix` removed, its encoding untouched.

    Sliced rather than re-encoded from the decoded path, which cannot be done
    at all and would be wrong if it could: uvicorn decodes `path` from these
    bytes, so `/%E8%B7%AF%E5%BE%84` arrives as `/路径` with no latin-1 form to
    encode back, and re-encoding `/delivery/a%2Fb` would hand the upstream
    `/a/b` — a separator it never received.

    The scan steps over whole escapes, because one decoded character can span
    three of them, and stops once it has decoded past the prefix: the work is
    bounded by the prefix in the routes file rather than by the caller's path.
    """
    text = raw.decode("latin-1")
    cut = 0
    while cut <= len(text):
        decoded = unquote(text[:cut])
        if decoded == prefix:
            # `_beneath` reads a path equal to its prefix as `/`; the bytes say
            # the same thing, so an empty tail is that same root.
            return text[cut:].encode("latin-1") or b"/"
        if len(decoded) > len(prefix):
            break
        cut += 3 if text[cut : cut + 1] == "%" else 1
    return raw


class _Enforcement:
    """Judge every MCP call, and answer for the ones that do not pass.

    **An ASGI layer above the MCP server, not a middleware inside it**, and that
    placement is the reason this is a class rather than a hook. A refusal here is
    an HTTP status — 403 for a call that was judged and denied, 503 for one that
    could not be judged at all. Inside FastMCP the same refusal is a JSON-RPC
    error, which the control plane's denial contract does not describe and an
    operator cannot read off a status line.

    Sitting above costs the parsed message: this is handed bytes and does its own
    parsing. It buys something worth more than it costs — the raw scope carries
    **every** `x-rail` value, so a repeated header is visible here as the two
    values it is, where anything downstream has already collapsed them and
    destroyed the evidence the contract says to check before reading the value.

    A session or discovery message — ``initialize``, ``tools/list`` and the
    rest `core.endpoint.DISCOVERY_METHODS` names — is forwarded before any
    of the below and reported to nobody: nothing in it is a call, and judging
    it would let a rule bound to one endpoint close the session in which every
    other endpoint is reached. Enforcement is per ``tools/call``.

    Three outcomes for a call, and only one is a denial:

      * **A policy matched** — 403, and the denial reported to Rail Center naming
        the policy that actually matched. Under `observe` the same walk runs and
        the same verdict is logged, the request is forwarded, and **nothing is
        reported**: a denial table filled from a mode that is explicitly not
        enforcing leaves an operator unable to tell which rows stopped traffic.
      * **Nothing could judge it** — 503 and **no denial report**. No policy
        decided, so naming one would attribute a verdict nobody reached, and a
        403 would tell the caller their ticket was judged and rejected when the
        ruleset could not be applied at all. Two cases: no bundle ever held, and
        a condition outside this build's grammar. Both are logged at error level
        naming what could not be read, because that line is the signal that Rail
        Center and this gateway have drifted.
      * **Nothing matched** — the body is replayed and the call goes on exactly
        as it would have.

    All three are answers to a call, which is a POST whose body finished
    arriving. A request the caller abandoned mid-upload is none of them: it is
    logged and replayed downstream, and reaches the walk not at all.
    """

    def __init__(
        self,
        app: ASGIApp,
        holder: BundleHolder,
        *,
        rail_center_url: str,
        auth: dict[str, str],
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._app = app
        self._holder = holder
        self._reporter = DenialReporter(rail_center_url, auth, transport=transport)

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or scope.get("method") != "POST":
            # Only a POST carries a call to judge. `/health`, `/ready` and the
            # GET that opens the event stream name no endpoint.
            await self._app(scope, receive, send)
            return

        body, replay, complete = await _drained(receive)
        if not complete:
            # **A request that never finished arriving is not a call**, so it is
            # not judged and no denial is reported for it. The bytes that did
            # arrive do not parse, which resolves `unrecognised` and faces the
            # whole chain — so judging a fragment attributes a policy denial to
            # a named agent over a call the ruleset may well allow, and Rail
            # Center records that attribution without re-deriving it.
            #
            # Nothing is answered instead, because there is nobody left to
            # answer: a body ends short here only when `http.disconnect` arrived,
            # and uvicorn discards whatever this layer composes once the client
            # has gone. The log line is the whole of the operator's signal, and
            # the replay still carries the fragment and the disconnect down to
            # the app below, which is where an abort has always been visible.
            log.info(
                "%s abandoned before its body finished arriving; not judged",
                safe_for_log(scope.get("path") or "the request"),
            )
            await self._app(scope, replay, send)
            return
        verdict = judge(
            self._holder,
            scope.get("path") or "/",
            body,
            _x_rail_values(scope),
            _x_rail_status_values(scope),
        )
        if verdict.report is not None:
            self._reporter.send(verdict.report)
        if verdict.status is not None:
            await _refuse(send, verdict.status, verdict.reason)
            return
        await self._app(scope, replay, send)


async def _drained(receive):
    """The request body, a `receive` that hands it over once more, and whether
    the body finished arriving.

    An ASGI body is a stream that can be read once, so a layer that looks at it
    has to put it back for whatever runs next. What the replay hands over is
    what this actually received, in the order it arrived; everything past it
    falls through to the original `receive`.

    **A disconnect is not the end of a body.** `http.disconnect` carries neither
    `body` nor `more_body`, so reading it as the last chunk would end the drain
    on a body that never finished arriving and then present that fragment
    downstream as a complete request — while swallowing the disconnect itself,
    which is the one message telling the app below the caller is gone. It ends
    the drain here too, because nothing further is coming, but it is replayed as
    the disconnect it is and the truncated fragment keeps its `more_body: True`.

    That disconnect is also the one exit from this drain that returns less than
    the caller meant to send, so the third value is what a reader above needs to
    tell a request from a fragment of one — and it says nothing to anyone who
    does not ask, which is how a fragment came to be judged as a call.
    """
    chunks: list[bytes] = []
    disconnected = False
    more = True
    while more:
        message = await receive()
        if message.get("type") == "http.disconnect":
            disconnected = True
            break
        chunks.append(message.get("body", b""))
        more = message.get("more_body", False)
    body = b"".join(chunks)

    pending: list[dict[str, Any]] = []
    if not disconnected:
        pending.append({"type": "http.request", "body": body, "more_body": False})
    else:
        if chunks:
            pending.append({"type": "http.request", "body": body, "more_body": True})
        pending.append({"type": "http.disconnect"})

    async def replay():
        if pending:
            return pending.pop(0)
        return await receive()

    return body, replay, not disconnected


async def _refuse(send, status: int, reason: str) -> None:
    """Answer the caller directly, without the MCP server seeing the request."""
    payload = refusal_body(reason)
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload})


def _x_rail_values(scope) -> list[str] | None:
    """Every `x-rail` value on the request, or None when there are none.

    **Every one, and that is the point.** The contract refuses a repeated
    `x-rail` outright and says the check cannot be deferred: once a platform has
    collapsed two values into one the evidence is gone. Reading the raw scope is
    what makes that impossible to lose — a header dict or Starlette's
    `Headers.get` would each hand back a single value, admitting a ticket an
    attacker chose by sending the header twice.

    Latin-1 because that is how a header's bytes map to `str` on this side. The
    ticket's own decoding is `parse_rail_header`'s, and is strict UTF-8 over the
    base64 it decodes.
    """
    found = [v.decode("latin-1") for k, v in scope.get("headers", ()) if k == b"x-rail"]
    return found or None


def _x_rail_status_values(scope) -> list[str] | None:
    """Every `x-rail-status` value on the request, or None when there are none.

    Every one, so a repeated header reaches the reporter as the two claims it is.
    """
    found = [
        v.decode("latin-1")
        for k, v in scope.get("headers", ())
        if k == b"x-rail-status"
    ]
    return found or None


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


def main() -> None:
    """Serve, on the configured port.

    The entry point exists so that `RAIL_GATEWAY_PORT` reaches the socket. A
    `CMD` naming the port on the uvicorn command line reads as equivalent and
    is not: the variable would be validated by `port()` and then ignored, so an
    operator who set it would get a gateway listening somewhere else and no
    error saying so.
    """
    import uvicorn

    configure_logging()
    # No `timeout_graceful_shutdown`: it was tried and does not do the job.
    # A tool call's answer travels on a streamable-http stream that uvicorn's
    # connection wait does not cover, so SIGTERM abandons a call in flight
    # whatever the timeout says — measured, the process exits in under a second
    # and the caller hangs to its own limit with no response. A value longer
    # than `docker stop`'s ten seconds would be SIGKILLed before it helped.
    # Draining this properly needs the ASGI app to hold the shutdown until its
    # streams finish, which this change does not build.
    uvicorn.run(build_app(), host="0.0.0.0", port=port())
