"""Running the holder for the life of the process."""

import asyncio
import logging
from collections.abc import Awaitable, Callable

import httpx
import pytest

from gateway.core import lifecycle
from gateway.core.bundle.client import FETCH_DEADLINE_SECONDS, BundleHolder
from gateway.core.lifecycle import STARTUP_FETCH_GRACE_SECONDS, running

GATEWAY_SLUG = "edge"

POLICY_BUNDLE = {
    "schema_version": "1.0",
    "content_hash": "v1",
    "policies": [
        {"id": "5c8f1e42-0000-4000-8000-0000000000a1", "name": "P", "priority": 1}
    ],
    "bindings": [],
}

#: How many turns of the event loop to allow before concluding something did
#: not happen.
TURNS = 200


def unreachable() -> httpx.Response:
    return httpx.Response(503)


def serving_a_bundle() -> httpx.Response:
    return httpx.Response(200, json=POLICY_BUNDLE)


def holder_serving(
    answer: Callable[[], httpx.Response],
    *,
    sleep: Callable[[float], Awaitable[None]] | None = None,
) -> BundleHolder:
    """A holder whose control plane is `answer`, refreshing only when `sleep`
    is released."""
    return BundleHolder(
        "http://rail-center.test",
        {},
        GATEWAY_SLUG,
        interval_seconds=3600,
        transport=httpx.MockTransport(lambda _request: answer()),
        sleep=sleep,
    )


async def _until(predicate, what: str) -> None:
    """Let the loop run until `predicate` holds, or fail saying what did not."""
    for _ in range(TURNS):
        if predicate():
            return
        await asyncio.sleep(0)
    raise AssertionError(what)


async def _settle() -> None:
    """Let everything pending run, for an assertion that something did *not*."""
    for _ in range(TURNS):
        await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_the_refresh_loop_is_retired_when_the_served_life_fails():
    """The ordinary shutdown is covered above; this is the other exit. A loop
    left running holds the event loop open and uvicorn's shutdown waits on it,
    so the worst shape of this defect is a process that will not go away —
    and a `stop()` reached only on the clean path is exactly that.

    The lifespan is driven directly because the failure has to happen *inside*
    the served life, which is the one place an ASGI client cannot reach.
    """
    fetches = 0
    resume = asyncio.Event()

    def answer() -> httpx.Response:
        nonlocal fetches
        fetches += 1
        return unreachable()

    async def sleep(_seconds: float) -> None:
        await resume.wait()
        resume.clear()

    holder = holder_serving(answer, sleep=sleep)

    with pytest.raises(RuntimeError, match="the served life"):
        async with running(holder):
            assert fetches == 1, "the lifespan did not fetch on startup"
            raise RuntimeError("the served life of the app failed")

    resume.set()
    await _settle()
    assert fetches == 1, "the refresh loop outlived the failure"


def test_the_startup_grace_is_short_enough_to_be_worth_bounding():
    """The shipped magnitude, which nothing else in the suite reads: every test
    that exercises the grace monkeypatches it, so it can be widened to any
    number at all on a green run. Widened, it is not a bound — it restores a
    `/health` answering *connection refused* for longer than a default
    Kubernetes liveness probe (`periodSeconds: 10`, `failureThreshold: 3`)
    waits before killing the container, and the next start repeats the wait.

    Bounded at half that window, so a probe still has a whole failure's margin
    left when the socket finally binds, and strictly under the holder's own
    deadline, since a grace at or past it is the unbounded wait written out.
    Nonzero at the other end: a grace of nothing never awaits the first fetch
    at all, and `/ready` then answers before any attempt has established what
    it is reporting.
    """
    assert 0 < STARTUP_FETCH_GRACE_SECONDS <= 15.0
    assert STARTUP_FETCH_GRACE_SECONDS < FETCH_DEADLINE_SECONDS


@pytest.mark.asyncio
async def test_a_first_fetch_that_answers_past_the_grace_still_arrives(monkeypatch):
    """`asyncio.wait` and not `wait_for`, whose timeout cancels what it waited
    on. The fetch left running past the grace is the one that creates the
    refresh loop — `start()` makes the loop after the first fetch returns — so
    cancelling it strands a gateway that is unready for ever and never retries,
    which is the one outcome `running` says the design rules out. The
    test above cannot see this: its fetch never answers at all, so a cancelled
    one and an abandoned one write the same line.

    The control plane here is slow rather than dead, which is the case that
    tells the two apart: it answers a good bundle, but only after the grace has
    already elapsed and the process has already claimed to be up.
    """
    monkeypatch.setattr(lifecycle, "STARTUP_FETCH_GRACE_SECONDS", 0.01)
    fetches = 0
    answer = asyncio.Event()
    resume = asyncio.Event()

    async def answers_only_when_released(_request) -> httpx.Response:
        nonlocal fetches
        fetches += 1
        await answer.wait()
        return serving_a_bundle()

    async def sleep(_seconds: float) -> None:
        await resume.wait()
        resume.clear()

    holder = BundleHolder(
        "http://rail-center.test",
        {},
        GATEWAY_SLUG,
        interval_seconds=3600,
        transport=httpx.MockTransport(answers_only_when_released),
        sleep=sleep,
    )

    async with running(holder):
        assert holder.current() is None, "the grace was meant to elapse first"
        answer.set()
        await _until(
            lambda: holder.current() is not None,
            "the fetch left running past the grace never delivered its bundle",
        )
        # And the loop it creates on the way out is really there: a cancelled
        # first fetch leaves nothing to refresh, which is the half of this that
        # never recovers.
        resume.set()
        await _until(lambda: fetches == 2, "the refresh loop was never created")


@pytest.mark.asyncio
async def test_a_first_fetch_still_in_flight_is_retired_with_the_app(monkeypatch):
    """The other half of the same `finally`, and the same failure shape as the
    refresh loop above. Past the grace the fetch is deliberately left running,
    so the only thing that ever ends it is the shutdown — and one that does not
    leaves an open socket to Rail Center outliving the application for up to the
    holder's deadline, holding the event loop open while uvicorn's shutdown
    waits on it. A process that will not go away is the worst shape an
    orchestrator can be handed, which is why `stop()` alone is not enough here.
    """
    monkeypatch.setattr(lifecycle, "STARTUP_FETCH_GRACE_SECONDS", 0.01)
    retired = asyncio.Event()

    class StillFetching(BundleHolder):
        async def start(self):
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                retired.set()
                raise

    holder = StillFetching(
        "http://rail-center.test",
        {},
        GATEWAY_SLUG,
        interval_seconds=3600,
        transport=httpx.MockTransport(lambda _request: unreachable()),
    )

    async with running(holder):
        pass

    await _settle()
    assert retired.is_set(), "the first fetch outlived the application"


@pytest.mark.asyncio
async def test_a_first_fetch_that_raises_past_the_grace_is_still_said_out_loud(
    monkeypatch, caplog
):
    """Nothing in the lifespan catches, and a raise before the grace elapses
    refuses the start. After it, the start has already been claimed and the
    raise can no longer refuse anything — so the log is the only place left to
    say it, and swallowed it is a gateway permanently unready for a reason
    nothing ever wrote down."""
    monkeypatch.setattr(lifecycle, "STARTUP_FETCH_GRACE_SECONDS", 0.01)
    released = asyncio.Event()

    class RaisesLate(BundleHolder):
        async def start(self):
            await released.wait()
            raise RuntimeError("a defect the grace had already elapsed on")

    holder = RaisesLate(
        "http://rail-center.test",
        {},
        GATEWAY_SLUG,
        interval_seconds=3600,
        transport=httpx.MockTransport(lambda _request: unreachable()),
    )

    with caplog.at_level(logging.ERROR, logger="gateway"):
        async with running(holder):
            released.set()
            await _settle()

    written = "\n".join(caplog.messages)
    assert "the first policy bundle fetch raised" in written, written
    assert "a defect the grace had already elapsed on" in caplog.text
