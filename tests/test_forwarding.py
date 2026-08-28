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

    `FastMCP.mount` would prefix every tool with its namespace, which is right
    for a proxy fronting several servers and wrong here: a renamed tool matches
    no endpoint the control plane registered, and the mismatch shows up as a
    policy that silently never applies rather than as an error.
    """
    async with Client(StreamableHttpTransport(url=f"{gateway_url}/mcp")) as client:
        names = sorted(tool.name for tool in await client.list_tools())

    assert names == ["track_package"]


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
