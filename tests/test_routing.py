"""One gateway, several upstreams, told apart by the prefix a request arrived under.

Every test here builds **more than one route**, which is the shape the rest of
the suite never has: a single-upstream gateway strips nothing, so the whole
dispatch layer reduces to a pass-through and nothing it does can be wrong. Two
of them is where a prefix is matched, removed, forwarded and composed into an
endpoint key, and where a sub-app that was never started answers 500.

The upstreams are real MCP servers on ephemeral ports, for the reason
`tests/conftest.py` gives: the gateway reaches its upstream as an MCP client, so
an in-process transport would exercise a shape only the suite has.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

import httpx
import pytest
import pytest_asyncio
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport

from gateway.routes import Route
from gateway.server import _raw_beneath, _under_prefix, build_app
from tests.conftest import (
    RAIL_CENTER,
    _free_port,
    holder_serving,
    serve,
    unreachable,
)


class Seen:
    """What reached one upstream: the paths, and the headers that came with them."""

    def __init__(self) -> None:
        self.paths: list[str] = []
        self.headers: list[dict[str, str]] = []

    def header(self, name: str) -> list[str]:
        return [headers[name] for headers in self.headers if name in headers]


@asynccontextmanager
async def upstream_named(label: str, seen: Seen):
    """An MCP server whose one tool reports which server it is.

    The label is the assertion: a test about routing has to distinguish *which*
    upstream answered, which a fixture returning the same string from both
    cannot do.
    """
    server = FastMCP(name=label)

    @server.tool
    def whoami() -> str:
        return label

    class Record:
        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            if scope["type"] == "http":
                seen.paths.append(scope["path"])
                seen.headers.append(
                    {k.decode().lower(): v.decode() for k, v in scope["headers"]}
                )
            await self.app(scope, receive, send)

    port = _free_port()
    async with serve(Record(server.http_app(transport="streamable-http")), port):
        yield f"http://127.0.0.1:{port}/mcp"


@asynccontextmanager
async def gateway_for(routes: list[Route]):
    """A gateway fronting `routes`, holding no bundle.

    The holder is injected and `rail_center` is passed, so nothing here reads the
    environment — which is also what makes this a standing check that a second
    route does not go looking for `RAIL_CENTER_URL` on its own behalf.
    """
    port = _free_port()
    app = build_app(
        routes, holder_serving(unreachable), plugin=True, rail_center=RAIL_CENTER
    )
    async with serve(app, port):
        yield f"http://127.0.0.1:{port}"


@pytest_asyncio.fixture
async def two_upstreams():
    """`delivery` and `finretail`, each a real MCP server, with what they saw."""
    delivery, finretail = Seen(), Seen()
    async with (
        upstream_named("delivery", delivery) as delivery_url,
        upstream_named("finretail", finretail) as finretail_url,
    ):
        yield (delivery_url, delivery), (finretail_url, finretail)


def _scope(path: str, *, headers: list[tuple[bytes, bytes]] | None = None) -> dict:
    """An ASGI scope shaped the way uvicorn hands one over."""
    return {
        "type": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "root_path": "",
        "headers": list(headers or []),
    }


def _header(scope: dict, name: bytes) -> list[bytes]:
    return [value for key, value in scope["headers"] if key == name]


async def call_whoami(base: str, prefix: str, **kwargs) -> str:
    async with Client(
        StreamableHttpTransport(url=f"{base}{prefix}/mcp", **kwargs)
    ) as client:
        result = await client.call_tool("whoami", {})
    return result.content[0].text


@pytest.mark.asyncio
async def test_every_upstream_answers_not_only_the_first(two_upstreams):
    """The capability this layer exists to add, asserted on both routes.

    A sub-app whose lifespan never ran has no `StreamableHTTPSessionManager`
    task group, and answers 500 to everything — so a gateway that starts the
    first route only serves exactly one upstream while reporting itself healthy.
    """
    (delivery_url, _), (finretail_url, _) = two_upstreams
    routes = [
        Route("delivery", delivery_url, "/delivery"),
        Route("finretail", finretail_url, "/finretail"),
    ]
    async with gateway_for(routes) as base:
        assert await call_whoami(base, "/delivery") == "delivery"
        assert await call_whoami(base, "/finretail") == "finretail"


@pytest.mark.asyncio
async def test_the_prefix_is_removed_before_the_sub_app_sees_it(two_upstreams):
    """The path the upstream serves, not the one the agent addressed.

    The endpoint key is composed from this path, so a prefix left on it would
    put the gateway's own mount point into every key the control plane is asked
    about.
    """
    (delivery_url, delivery), (finretail_url, _) = two_upstreams
    routes = [
        Route("delivery", delivery_url, "/delivery"),
        Route("finretail", finretail_url, "/finretail"),
    ]
    async with gateway_for(routes) as base:
        await call_whoami(base, "/delivery")

    assert delivery.paths, "the upstream was never reached"
    assert all(path.startswith("/mcp") for path in delivery.paths), delivery.paths


def test_the_prefix_travels_on_as_x_forwarded_prefix():
    """Where this gateway serves the route, in Traefik's spelling.

    Asserted on the scope the sub-app is handed, which is as far as the header
    goes: the gateway reaches its upstream as an MCP client rather than by
    proxying the HTTP request, and forwards none of the caller's headers.
    """
    rewritten = _under_prefix(
        _scope("/delivery/mcp"), Route("delivery", "http://u", "/delivery"), "/mcp"
    )

    assert _header(rewritten, b"x-forwarded-prefix") == [b"/delivery"]


def test_a_prefix_outside_latin_1_is_announced_rather_than_raising():
    """A header value is bytes, and `/路径` has no latin-1 spelling to send.

    The routes loader accepts the prefix, so encoding it here is the only place
    the deployment can fail — and it would fail per request, inside the ASGI
    app, on a gateway that started cleanly.
    """
    rewritten = _under_prefix(
        {
            "type": "http",
            "path": "/路径/mcp",
            "raw_path": "/路径/mcp".encode(),
            "root_path": "",
            "headers": [],
        },
        Route("delivery", "http://u", "/路径"),
        "/mcp",
    )

    assert _header(rewritten, b"x-forwarded-prefix") == [b"/%E8%B7%AF%E5%BE%84"]


def test_the_root_prefix_announces_no_prefix_at_all():
    """The single-upstream deployment strips nothing and has nothing to declare.

    An empty header would tell a framework beneath that it is mounted at the
    empty string, which is a claim rather than the absence of one.
    """
    rewritten = _under_prefix(
        _scope("/mcp"), Route("delivery", "http://u", "/"), "/mcp"
    )

    assert _header(rewritten, b"x-forwarded-prefix") == []


def test_a_caller_cannot_supply_its_own_x_forwarded_prefix():
    """The header says where *this gateway* serves the route, so only it sets it.

    A caller's own value surviving alongside the real one lets it tell whatever
    reads the header that the route is mounted somewhere it is not — the same
    class of forgery the `x-rail` boundary exists to close.
    """
    scope = _scope("/delivery/mcp", headers=[(b"x-forwarded-prefix", b"/forged")])
    rewritten = _under_prefix(scope, Route("delivery", "http://u", "/delivery"), "/mcp")

    assert _header(rewritten, b"x-forwarded-prefix") == [b"/delivery"]


@pytest.mark.asyncio
async def test_a_sibling_prefix_is_not_a_parent(two_upstreams):
    """`/delivery` claims `/delivery/mcp` and never `/delivery-eu/mcp`.

    Matching on the bare string rather than on a path boundary routes every
    longer-named sibling to whichever of them is checked first.
    """
    (delivery_url, _), (finretail_url, _) = two_upstreams
    routes = [
        Route("delivery", delivery_url, "/delivery"),
        Route("eu", finretail_url, "/delivery-eu"),
    ]
    async with gateway_for(routes) as base:
        assert await call_whoami(base, "/delivery") == "delivery"
        assert await call_whoami(base, "/delivery-eu") == "finretail"


@pytest.mark.asyncio
async def test_an_unmounted_sibling_is_refused_by_this_layer(two_upstreams):
    """With only `/delivery` mounted, `/delivery-eu/mcp` belongs to no route.

    Asserted on **who** refused it rather than on the status: a dispatch that
    matches on the bare string hands the request to `/delivery` with `-eu/mcp`
    left over, and that sub-app answers its own 404 — the same status for a
    request this layer should never have routed at all. Longest-prefix-first
    ordering hides the same fault whenever the sibling is mounted too, so the
    case that can see it is the one where it is not.
    """
    (delivery_url, _), (finretail_url, _) = two_upstreams
    routes = [
        Route("delivery", delivery_url, "/delivery"),
        Route("finretail", finretail_url, "/finretail"),
    ]
    async with gateway_for(routes) as base, httpx.AsyncClient() as client:
        response = await client.post(f"{base}/delivery-eu/mcp")

    assert response.status_code == 404
    assert response.json() == {"error": "no upstream is mounted at /delivery-eu/mcp"}


@pytest.mark.asyncio
async def test_an_unmounted_path_is_refused_rather_than_guessed(two_upstreams):
    """A request matching no route has no answer this gateway could give.

    Falling back to the first upstream would forward a call the operator never
    mounted, under a key composed from a path nobody serves — and that fallback
    answers 404 as well, from the sub-app instead of from here, so the refusal
    this layer writes is what tells the two apart.
    """
    (delivery_url, _), (finretail_url, _) = two_upstreams
    routes = [
        Route("delivery", delivery_url, "/delivery"),
        Route("finretail", finretail_url, "/finretail"),
    ]
    async with gateway_for(routes) as base, httpx.AsyncClient() as client:
        response = await client.post(f"{base}/nowhere/mcp")

    assert response.status_code == 404
    assert response.json() == {"error": "no upstream is mounted at /nowhere/mcp"}


@pytest.mark.asyncio
async def test_health_and_ready_are_the_gateways_own_at_the_root(two_upstreams):
    """Answered off the primary, above the routes rather than through one.

    With both prefixes non-root, a `/health` that fell through to the dispatch
    loop would match nothing and 404 — so the gateway would report itself dead
    to whatever is watching it.
    """
    (delivery_url, _), (finretail_url, _) = two_upstreams
    routes = [
        Route("delivery", delivery_url, "/delivery"),
        Route("finretail", finretail_url, "/finretail"),
    ]
    async with gateway_for(routes) as base, httpx.AsyncClient() as client:
        health = await client.get(f"{base}/health")
        ready = await client.get(f"{base}/ready")

    assert health.status_code == 200
    assert health.json() == {"status": "ok"}
    # Unready because this gateway's control plane is down, which is the
    # holder's answer — and the holder is the primary's.
    assert ready.status_code == 503


@pytest.mark.asyncio
async def test_a_second_route_polls_no_control_plane_of_its_own(two_upstreams):
    """One holder for the gateway, so one poll loop against one bundle.

    A route after the first that resolved its own holder would answer `/ready`
    off an object nothing ever starts — permanently 503 — while the gateway's
    own readiness came from somewhere else entirely.
    """
    (delivery_url, _), (finretail_url, _) = two_upstreams
    routes = [
        Route("delivery", delivery_url, "/delivery"),
        Route("finretail", finretail_url, "/finretail"),
    ]
    async with gateway_for(routes) as base, httpx.AsyncClient() as client:
        response = await client.get(f"{base}/finretail/ready")

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_an_upstream_is_served_where_it_already_serves(two_upstreams):
    """`prefix: /mcp` — an upstream mounted at the path it serves.

    The prefix must be carried by exactly one of `path` and `root_path`:
    Starlette removes `root_path` from `path` itself, so a prefix in both is
    removed twice and this gateway serves nothing at all.
    """
    (delivery_url, _), _ = two_upstreams
    async with gateway_for([Route("delivery", delivery_url, "/mcp")]) as base:
        assert await call_whoami(base, "/mcp") == "delivery"


@pytest.mark.asyncio
async def test_a_doubled_prefix_is_not_served_as_a_single_one(two_upstreams):
    """`/a/a/mcp` is not `/a/mcp`, and must not be answered as though it were.

    Stripping the prefix twice serves a path the sub-app should refuse, while
    the enforcement layer above composed its key from the path as it arrived —
    so the decision, the log line and any denial name an endpoint nobody serves.
    """
    (delivery_url, _), _ = two_upstreams
    async with (
        gateway_for([Route("delivery", delivery_url, "/a")]) as base,
        httpx.AsyncClient() as client,
    ):
        response = await client.post(f"{base}/a/a/mcp")

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_a_path_outside_latin_1_is_refused_rather_than_raising(gateway_url):
    """An unauthenticated caller must not be able to raise inside the app.

    The rewrite runs for the root prefix too, so this is the default
    single-upstream deployment rather than anything the routing adds: a path
    carrying a character with no latin-1 spelling is a 404 like any other path
    nothing serves.
    """
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{gateway_url}/%E8%B7%AF%E5%BE%84")

    assert response.status_code == 404


def test_the_raw_path_keeps_the_encoding_it_arrived_with():
    """`raw_path` is sliced, never rebuilt from the decoded path.

    Re-encoding cannot represent a path uvicorn already decoded out of latin-1,
    and spells an escaped separator as a real one: `/a%2Fb` is one path segment
    containing a slash, and handing the upstream `/a/b` is two segments.
    """
    assert _raw_beneath(b"/delivery/a%2Fb", "/delivery") == b"/a%2Fb"
    assert _raw_beneath(b"/delivery/mcp", "/delivery") == b"/mcp"
    # A prefix the caller spelled with escapes still matches the decoded path,
    # so the slice has to find the boundary rather than assume its length.
    assert _raw_beneath(b"/%64elivery/mcp", "/delivery") == b"/mcp"
    # `_beneath` reads a path equal to its prefix as `/`; the bytes agree.
    assert _raw_beneath(b"/delivery", "/delivery") == b"/"
    # The root prefix strips nothing, including from a path with no latin-1 form.
    assert _raw_beneath(b"/%E8%B7%AF%E5%BE%84", "") == b"/%E8%B7%AF%E5%BE%84"


def test_the_prefix_is_carried_by_the_path_and_not_by_root_path():
    """Only one of them may hold it, or Starlette removes it a second time."""
    rewritten = _under_prefix(
        _scope("/delivery/mcp"), Route("delivery", "http://u", "/delivery"), "/mcp"
    )

    assert rewritten["path"] == "/mcp"
    assert rewritten["root_path"] == ""
