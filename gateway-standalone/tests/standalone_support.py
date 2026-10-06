"""What the gateway tests share that is not a fixture: servers, holders, routes.

Here rather than in `conftest.py` because a conftest is not importable under
`--import-mode=importlib`, and several tests call these directly rather than
asking for them as fixtures. The root `pyproject.toml` puts this folder on
`sys.path`; the name is this member's own so a sibling member's helpers can
never shadow it.
"""

import asyncio
import socket
import threading
import time
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager

import httpx
import uvicorn

from gateway.core.bundle.client import BundleHolder
from gateway.standalone.routes import Route


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


STARTUP_TIMEOUT_SEC = 10
SHUTDOWN_TIMEOUT_SEC = 10
LIFESPAN_TIMEOUT_SEC = 10

#: Where a test gateway reports denials, and the credential it uses. Injected
#: for the same reason the holder is: a suite that read the environment would
#: report to whatever `RAIL_CENTER_URL` happened to be set to on the machine.
RAIL_CENTER = ("http://rail-center.test", {})

#: The data source every test gateway fronts. The gateway composes no slug — it
#: is the first segment of a *bundle* key, which `strip_slug` removes — so this
#: names the one the bundles in this suite are published under, and is what a
#: fixture builds a full key from before the strip is asserted on.
SLUG = "delivery"


#: Where a test gateway listens for its one upstream. `/` — the single-upstream
#: deployment — so a path reaches the proxy unchanged and an endpoint key is
#: composed from `/mcp`, which is what the vectors carry. A test about routing
#: builds its own routes with prefixes.
def one_route(upstream: str, *, name: str = SLUG, prefix: str = "/") -> Route:
    return Route(name=name, url=upstream, prefix=prefix)


#: The gateway every test gateway is. Injected for the same reason `SLUG` is,
#: and a different value from it on purpose: a gateway's own identity and the
#: slug of a data source it fronts are two names, and a suite that used one
#: string for both would pass with them confused.
GATEWAY_SLUG = "edge"

#: One valid bundle, for tests whose subject is what holding one does rather
#: than what makes one valid. `gateway-core/tests/test_bundle_holder.py` keeps its own
#: `bundle()` factory: that one exists to vary content hashes and policies
#: across a hundred cases, and this is a single fixed example — collapsing them
#: would give that factory a second caller with different reasons to change it.
POLICY_BUNDLE = {
    "schema_version": "1.0",
    "content_hash": "v1",
    "policies": [
        {"id": "5c8f1e42-0000-4000-8000-0000000000a1", "name": "P", "priority": 1}
    ],
    "bindings": [],
}


def unreachable() -> httpx.Response:
    """A control plane that is down, so the holder holds nothing.

    The state most of this suite runs in, and the one a fresh deployment starts
    in: `/ready` answers 503 and everything else behaves exactly as it does with
    a bundle held, because nothing consults one.
    """
    return httpx.Response(503)


def serving_a_bundle() -> httpx.Response:
    """A control plane answering with `POLICY_BUNDLE`."""
    return httpx.Response(200, json=POLICY_BUNDLE)


def holder_serving(
    answer: Callable[[], httpx.Response],
    *,
    interval_seconds: int = 3600,
    sleep: Callable[[float], Awaitable[None]] | None = None,
) -> BundleHolder:
    """A holder whose control plane is `answer` rather than the network.

    `answer` is called per fetch rather than given as a response, so a test can
    change what Rail Center says between two of them — which is the only way to
    ask whether `/ready` reads the holder live or cached a verdict at startup.

    The interval is an hour by default, so the refresh loop never fires and a
    test wanting a second fetch asks for one. A short interval here would make
    every assertion about what is held a race with a background task. A test
    that needs the loop to take a turn passes `sleep` and releases it, which is
    the same thing said without the clock in it.
    """
    return BundleHolder(
        "http://rail-center.test",
        {},
        GATEWAY_SLUG,
        interval_seconds=interval_seconds,
        transport=httpx.MockTransport(lambda _request: answer()),
        sleep=sleep,
    )


@asynccontextmanager
async def running(app):
    """An app with its lifespan run the way uvicorn runs it, and a client for it.

    For the routes that answer without touching the upstream — `/health` and
    `/ready`. `serve` below exists because the *MCP* path cannot be exercised
    in-process; these two are plain ASGI requests, identical to what uvicorn
    delivers, and running them on the test's own loop is what lets a test drive
    the holder directly and assert on the result without sleeping on a thread.

    A startup that fails is raised rather than waited on: the app sends no
    `startup.complete` in that case, so without the check the defect arrives as
    a hang and the log says only that the job was cancelled.
    """
    to_app: asyncio.Queue = asyncio.Queue()
    from_app: asyncio.Queue = asyncio.Queue()
    scope = {"type": "lifespan", "asgi": {"version": "3.0"}}
    task = asyncio.create_task(app(scope, to_app.get, from_app.put))
    try:
        await to_app.put({"type": "lifespan.startup"})
        message = await asyncio.wait_for(from_app.get(), LIFESPAN_TIMEOUT_SEC)
        if message["type"] != "lifespan.startup.complete":
            raise RuntimeError(f"the app refused to start: {message}")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://gateway.test"
        ) as client:
            yield client
        await to_app.put({"type": "lifespan.shutdown"})
        await asyncio.wait_for(task, LIFESPAN_TIMEOUT_SEC)
    finally:
        # A no-op on the ordinary path, where the task has already returned. On
        # every other one it is what stops a lifespan caught mid-startup, or
        # wedged in shutdown, from outliving the test and refreshing into the
        # next.
        task.cancel()


@asynccontextmanager
async def serve(app, port: int):
    """Run an ASGI app on its own event loop, in a thread, until the block exits.

    A thread rather than a task on the test's own loop, and this is the whole
    reason the tests below are stable. Two servers and a client sharing one loop
    is not the shape a deployment has, and it deadlocks: a call arrives at the
    gateway, whose handler opens a session to the upstream, whose handler is a
    callback on the same loop that is already inside the gateway's handler. It
    resolves when every step yields promptly and hangs when one does not, so it
    passes on a fast machine and times out on a slow one — which is exactly what
    it did, silently, on the CI runner while passing on every laptop.

    `Server.run` makes its own loop, which is also what uvicorn does in
    production, and skips signal handling off the main thread rather than
    installing handlers the suite then has to live with.
    """
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + STARTUP_TIMEOUT_SEC
        while not server.started:
            # `started` never turns true if the bind failed — uvicorn exits
            # inside the thread — so waiting on it alone spins until the
            # runner's own limit. The thread's death is what reports it.
            if not thread.is_alive():
                raise RuntimeError("the server exited before it started serving")
            if time.monotonic() > deadline:
                raise RuntimeError(
                    f"the server did not start within {STARTUP_TIMEOUT_SEC}s"
                )
            await asyncio.sleep(0.02)
        yield
    finally:
        server.should_exit = True
        await asyncio.to_thread(thread.join, SHUTDOWN_TIMEOUT_SEC)
        if thread.is_alive():
            raise RuntimeError(
                f"the server did not stop within {SHUTDOWN_TIMEOUT_SEC}s"
            )
