"""What this component does today: receive a call and forward it, unchanged."""

from __future__ import annotations

import httpx
import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport


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
    reached = []

    async def sampling_handler(messages, params, ctx):
        # A caller that *can* answer. Without this the call fails because this
        # client declared no sampling capability, and the test would pass
        # whether or not the gateway relayed — which is the shape of an
        # assertion that proves nothing.
        reached.append(messages)
        return "the caller's model answered"

    async with Client(
        StreamableHttpTransport(url=f"{gateway_url}/mcp"),
        sampling_handler=sampling_handler,
    ) as client:
        result = await client.call_tool("reach_into_the_caller", {})

    assert not reached, "the upstream reached the caller's model"
    assert result.content[0].text.startswith("refused:")
