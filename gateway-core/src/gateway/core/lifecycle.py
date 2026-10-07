"""Start and stop the bundle holder with the process, and report readiness."""

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from gateway.core.bundle.client import BundleHolder

log = logging.getLogger(__name__)

#: How long the lifespan waits on the first policy bundle fetch before serving
#: anyway. Not the holder's deadline: this one is paid by `/health`, which
#: answers connection-refused until it elapses, so it is set against an
#: orchestrator's patience rather than against a control plane's.
STARTUP_FETCH_GRACE_SECONDS = 5.0


@asynccontextmanager
async def running(holder: BundleHolder | None) -> AsyncIterator[None]:
    """Run `holder` for the life of the block, and stop it after.

    A None holder has nothing to start, and the block is entered at once.

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


def is_ready(holder: BundleHolder | None) -> bool:
    """Whether there is a ruleset to decide with: always without a holder,
    and once a bundle is held with one."""
    return holder is None or holder.current() is not None
