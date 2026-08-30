"""What this component does today: receive a call and forward it, unchanged."""

from __future__ import annotations

import httpx
import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError

from gateway.server import build_app


@pytest.mark.asyncio
async def test_a_call_reaches_the_upstream_and_its_answer_comes_back(gateway_url):
    """The whole transport path in one assertion."""
    async with Client(StreamableHttpTransport(url=f"{gateway_url}/mcp")) as client:
        result = await client.call_tool("track_package", {"tracking_number": "77123"})

    assert result.content[0].text == "delivered:77123"


@pytest.mark.asyncio
async def test_tool_names_are_not_rewritten(gateway_url):
    """An endpoint key is `<datasource_slug>.<tool_name>`, and the agents were
    prompted with the upstream's names.

    `FastMCP.mount` prefixes an upstream's tools when it is given a namespace,
    which is right for a proxy fronting several servers and wrong here. Serving
    the proxy directly is the shape that cannot acquire a prefix later; a
    renamed tool matches no endpoint the control plane registered, and shows up
    as a policy that silently never applies rather than as an error.
    """
    async with Client(StreamableHttpTransport(url=f"{gateway_url}/mcp")) as client:
        names = sorted(tool.name for tool in await client.list_tools())

    assert names == ["reach_into_the_caller", "scan_batch", "track_package"]


@pytest.mark.asyncio
async def test_a_caller_cannot_put_its_own_x_rail_upstream(gateway_url, seen_headers):
    """The identity this component checks must not be one the caller supplied.

    `create_proxy` forwards incoming headers by default. Left on, `x-rail:
    FORGED` arrives at the upstream unchanged and everything downstream trusts
    it — so this asserts the boundary holds rather than that a line is present.
    """
    async with Client(
        StreamableHttpTransport(url=f"{gateway_url}/mcp", headers={"x-rail": "FORGED"})
    ) as client:
        await client.call_tool("track_package", {"tracking_number": "77123"})

    assert seen_headers, "the upstream was never reached"
    assert not any("x-rail" in headers for headers in seen_headers)


@pytest.mark.asyncio
async def test_authorization_does_not_cross_either(gateway_url, seen_headers):
    """`authorization` rides the same path as `x-rail` and is re-included by
    fastmcp rather than stripped, so it is asserted separately."""
    async with Client(
        StreamableHttpTransport(
            url=f"{gateway_url}/mcp", headers={"authorization": "Bearer caller-token"}
        )
    ) as client:
        await client.call_tool("track_package", {"tracking_number": "77123"})

    assert seen_headers, "the upstream was never reached"
    assert not any("authorization" in headers for headers in seen_headers)


@pytest.mark.asyncio
async def test_health_reports_liveness(gateway_url):
    """Liveness only. It answers before anything this gateway decides with
    exists, which is why a later change has to give it a readiness half."""
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{gateway_url}/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_progress_notifications_survive_the_hop(gateway_url):
    """A tool call's second channel has to cross too.

    With a plain `Client` as the backend rather than a `ProxyClient`, fastmcp
    installs none of the relaying handlers: the call still returns "scanned",
    so nothing looks broken, while every progress notification is dropped on
    the way back. A silent partial forward is worse than a loud failure —
    this is what makes it loud.
    """
    seen: list[tuple[float, float | None]] = []

    async def on_progress(progress, total, message):
        seen.append((progress, total))

    async with Client(
        StreamableHttpTransport(url=f"{gateway_url}/mcp"), progress_handler=on_progress
    ) as client:
        result = await client.call_tool("scan_batch", {})

    assert result.content[0].text == "scanned"
    assert seen == [(1.0, 2.0), (2.0, 2.0)]


@pytest.mark.asyncio
async def test_the_upstream_cannot_reach_back_into_the_caller(gateway_url):
    """The second channel is relayed one way only.

    `ProxyClient` installs handlers for roots, sampling and elicitation as well
    as progress and logs. Those three are requests travelling *into* the
    caller: with them on, the service behind this gateway can enumerate the
    caller's roots, drive its model with a prompt of its choosing, and put a
    question in front of its human. The header boundary does not cover that
    direction, so the handlers are refused explicitly and this is what says so.
    """
    reached: list[str] = []

    # A caller that *can* answer all three. Without every one of these the
    # corresponding attempt fails for this client's own lack of capability, and
    # the assertion holds whether or not the gateway relayed — which is an
    # assertion that proves nothing, and was twice written that way here.
    async def sampling_handler(messages, params, ctx):
        reached.append("sampling")
        return "the caller's model answered"

    async def elicitation_handler(message, response_type, params, ctx):
        reached.append("elicitation")
        return "sk-CALLER-SECRET"

    async with Client(
        StreamableHttpTransport(url=f"{gateway_url}/mcp"),
        sampling_handler=sampling_handler,
        elicitation_handler=elicitation_handler,
        roots=["file:///caller/private"],
    ) as client:
        result = await client.call_tool("reach_into_the_caller", {})

    assert not reached, "the upstream reached the caller's model"
    # All three, not only the one with a handler on this side: deleting
    # roots=None or elicitation_handler=None otherwise leaves the suite green.
    assert result.content[0].text == "refused:all"


@pytest.mark.asyncio
async def test_an_upstream_failure_does_not_hand_the_caller_its_credential():
    """httpx names the URL it called in its error, and fastmcp puts that string
    in the JSON-RPC error it returns — so an ordinary 401 handed an
    unauthenticated caller the upstream's address and, where the URL carries
    one, its credential. A stale upstream key made every call a disclosure of
    it.

    This covers the `user:password@` form, which is moved into an Authorization
    header so it is not in the URL httpx names. **A credential in the query
    string is not covered** — `?api_key=` is how some hosted MCP endpoints
    route a request, so it has to stay in the URL, and it still reaches the
    caller in an upstream error. Closing that needs an error boundary the
    proxy's connection setup passes through, which this change does not have.
    """
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    from tests.conftest import _free_port, holder_serving, serve, unreachable

    async def always_401(_request):
        return JSONResponse({"error": "nope"}, status_code=401)

    upstream_port = _free_port()
    secret_url = f"http://svcuser:s3cret@127.0.0.1:{upstream_port}/mcp"
    refusing = Starlette(routes=[Route("/mcp", always_401, methods=["POST", "GET"])])

    gateway_port = _free_port()
    async with (
        serve(refusing, upstream_port),
        serve(
            build_app(secret_url, holder_serving(unreachable), slug="delivery"),
            gateway_port,
        ),
        httpx.AsyncClient() as client,
    ):
        response = await client.post(
            f"http://127.0.0.1:{gateway_port}/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "t", "version": "1"},
                },
            },
            headers={"accept": "application/json, text/event-stream"},
        )

    body = response.text
    assert "s3cret" not in body


@pytest.mark.asyncio
async def test_the_upstream_credential_still_travels(upstream, seen_headers):
    """`_split_credential` takes `user:password@` out of the URL so httpx cannot
    name it in an error. The credential still has to reach the upstream, on the
    same request — dropping it entirely would silently 401 every credentialed
    deployment, and nothing else here would notice.
    """
    from tests.conftest import _free_port, holder_serving, serve, unreachable

    scheme, rest = upstream.split("://", 1)
    credentialed = f"{scheme}://svcuser:s3cret@{rest}"

    port = _free_port()
    async with (
        serve(
            build_app(credentialed, holder_serving(unreachable), slug="delivery"), port
        ),
        Client(StreamableHttpTransport(url=f"http://127.0.0.1:{port}/mcp")) as c,
    ):
        await c.call_tool("track_package", {"tracking_number": "77123"})

    sent = [h.get("authorization") for h in seen_headers if "authorization" in h]
    assert sent, "no Authorization header reached the upstream"
    assert all(v == "Basic c3ZjdXNlcjpzM2NyZXQ=" for v in sent)


@pytest.mark.asyncio
async def test_an_unknown_tool_reports_itself_not_an_outage(gateway_url):
    """The error boundary must not swallow the upstream's own answers.

    Catching every exception rather than the transport ones turned `Unknown
    tool: 'no_such_tool'` into "the upstream service could not be reached", so
    a caller's typo read as an outage and the real answer never arrived.
    """
    async with Client(StreamableHttpTransport(url=f"{gateway_url}/mcp")) as client:
        with pytest.raises(ToolError) as caught:
            await client.call_tool("no_such_tool", {})

    assert "no_such_tool" in str(caught.value)
    assert "could not be reached" not in str(caught.value)
