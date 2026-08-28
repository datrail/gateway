"""A real upstream and a real gateway, both on ephemeral ports.

The gateway connects to its upstream as an MCP client, so the upstream cannot
be an in-process ASGI transport — it has to be reachable at a URL. Running both
under uvicorn is what makes these tests exercise the path a deployment uses
rather than a shape that only exists in the suite.
"""

from __future__ import annotations

import asyncio
import socket
from contextlib import asynccontextmanager

import pytest
import pytest_asyncio
import uvicorn
from fastmcp import Context, FastMCP

from gateway.server import build_app


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@asynccontextmanager
async def serve(app, port: int):
    """Run an ASGI app until the block exits."""
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    try:
        while not server.started:
            # `server.started` never turns true if the bind failed — uvicorn
            # exits inside the task — so waiting on it alone spins until the CI
            # runner's own limit. The task is what reports the failure.
            if task.done():
                await task
                raise RuntimeError("the server exited before it started serving")
            await asyncio.sleep(0.02)
        yield
    finally:
        server.should_exit = True
        await task


@pytest.fixture
def seen_headers() -> list[dict[str, str]]:
    """Every header set the upstream was sent, in order."""
    return []


@pytest_asyncio.fixture
async def upstream(seen_headers):
    """An MCP server with one tool, recording what reaches it."""
    server = FastMCP(name="upstream")

    @server.tool
    def track_package(tracking_number: str) -> str:
        return f"delivered:{tracking_number}"

    @server.tool
    async def reach_into_the_caller(ctx: Context) -> str:
        """A hostile upstream's move: ask the caller's side to do something.

        The gateway must refuse rather than relay, so this reports what it got
        instead of raising — the test asserts on the refusal.
        """
        try:
            await ctx.sample("say anything")
        except Exception as exc:  # noqa: BLE001 - the refusal is the result
            return f"refused:{type(exc).__name__}"
        return "relayed"

    @server.tool
    async def scan_batch(ctx: Context) -> str:
        """Reports progress on the way, so a test can check it survives."""
        await ctx.report_progress(1, 2)
        await ctx.report_progress(2, 2)
        return "scanned"

    class Record:
        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            if scope["type"] == "http" and scope["path"].startswith("/mcp"):
                seen_headers.append(
                    {k.decode().lower(): v.decode() for k, v in scope["headers"]}
                )
            await self.app(scope, receive, send)

    port = _free_port()
    async with serve(Record(server.http_app(transport="streamable-http")), port):
        yield f"http://127.0.0.1:{port}/mcp"


@pytest_asyncio.fixture
async def gateway_url(upstream):
    """The gateway, forwarding to the upstream fixture."""
    port = _free_port()
    async with serve(build_app(upstream), port):
        yield f"http://127.0.0.1:{port}"
