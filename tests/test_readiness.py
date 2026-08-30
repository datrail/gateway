"""Readiness, and the two things it must not become.

Feature 12 is one bit — *is a policy bundle held* — and almost every way of
getting it wrong is a way of answering a different question than the one asked:

* **Liveness must not learn it.** The remedies are opposite. A process that is
  not live should be replaced; a process that is not ready should be left alone
  to become ready. An orchestrator given one answer for both restarts a gateway
  whose only problem is a control plane it cannot reach, and restarting is the
  one action that cannot help.
* **Traffic must not depend on it.** Nothing consults the bundle yet, so a
  "not ready" that stops requests is an outage bought for no enforcement. The
  cases below assert the forward path is indifferent to the report, which is
  what makes wiring them together later a change that fails tests rather than
  one that passes quietly.

The state a fresh deployment starts in is *unready*, so it is the state most of
this suite already runs in: `conftest.gateway_url` never reaches its control
plane on purpose.
"""

from __future__ import annotations

import asyncio
import logging

import httpx
import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

from gateway import server
from gateway.bundle.client import FETCH_DEADLINE_SECONDS, BundleHolder
from gateway.server import _bundle_lifespan, build_app
from tests.conftest import (
    POLICY_BUNDLE,
    holder_serving,
    running,
    serving_a_bundle,
    unreachable,
)

#: Never reached — `build_gateway` validates this and nothing here forwards.
UPSTREAM = "http://upstream.invalid/mcp"

#: How many turns of the event loop to allow before concluding something did
#: not happen. Bounded rather than a sleep: everything these tests wait on is
#: in-memory, so what they are waiting for is the scheduler and not the clock.
TURNS = 200


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


# --- the report itself ----------------------------------------------------


@pytest.mark.asyncio
async def test_a_gateway_holding_no_bundle_is_not_ready():
    """`None` from `current()` is no ruleset, and there is nothing else it can
    honestly be reported as. 503, because the status code is the part every
    orchestrator reads without being taught to."""
    app = build_app(UPSTREAM, holder_serving(unreachable))

    async with running(app) as client:
        response = await client.get("/ready")

    assert response.status_code == 503
    assert response.json() == {"status": "not ready"}


@pytest.mark.asyncio
async def test_a_gateway_holding_a_bundle_is_ready():
    app = build_app(UPSTREAM, holder_serving(serving_a_bundle))

    async with running(app) as client:
        response = await client.get("/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


@pytest.mark.asyncio
async def test_the_report_does_not_carry_the_version_held():
    """The route is unauthenticated and shares a port with the MCP surface, so
    a version in the body is a public feed of when a customer's policy changed.
    The operator use it would serve is already served by the log line."""
    app = build_app(UPSTREAM, holder_serving(serving_a_bundle))

    async with running(app) as client:
        body = (await client.get("/ready")).text

    assert POLICY_BUNDLE["version"] not in body


@pytest.mark.asyncio
async def test_readiness_is_read_at_the_request_and_not_cached_at_startup():
    """A gateway that started before its control plane did must become ready
    without being restarted. A verdict computed once at startup passes both
    tests above and fails this one, which is the whole reason it is here."""
    answer = unreachable
    holder = holder_serving(lambda: answer())
    app = build_app(UPSTREAM, holder)

    async with running(app) as client:
        assert (await client.get("/ready")).status_code == 503

        answer = serving_a_bundle
        await holder.refresh()

        assert (await client.get("/ready")).status_code == 200


@pytest.mark.asyncio
async def test_a_failed_refresh_does_not_take_readiness_away():
    """The holder keeps the last usable bundle through a failed fetch, so the
    report has to keep saying ready. Reporting on the last *outcome* rather
    than on what is held would flip this to 503 while the gateway still holds
    everything it needs."""
    answer = serving_a_bundle
    holder = holder_serving(lambda: answer())
    app = build_app(UPSTREAM, holder)

    async with running(app) as client:
        assert (await client.get("/ready")).status_code == 200

        answer = unreachable
        await holder.refresh()

        assert (await client.get("/ready")).status_code == 200


@pytest.mark.asyncio
async def test_a_bundle_that_will_not_validate_leaves_the_gateway_unready():
    """`current()` is never a bundle that failed validation, so a control plane
    answering 200 with something unusable is not a control plane that made this
    gateway ready. The failure is Rail Center and this gateway having drifted,
    which is a different fault from an unreachable one and the same report."""

    def missing_its_policies() -> httpx.Response:
        return httpx.Response(200, json={"version": "v1"})

    app = build_app(UPSTREAM, holder_serving(missing_its_policies))

    async with running(app) as client:
        assert (await client.get("/ready")).status_code == 503


# --- liveness stays what it was -------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("label", "answer"),
    [("holding a bundle", serving_a_bundle), ("holding none", unreachable)],
)
async def test_liveness_is_the_same_answer_either_way(label, answer):
    """The one assertion that stops `/health` from acquiring a second job."""
    app = build_app(UPSTREAM, holder_serving(answer))

    async with running(app) as client:
        response = await client.get("/health")

    assert response.status_code == 200, label
    assert response.json() == {"status": "ok"}


# --- and traffic does not depend on either --------------------------------


@pytest.mark.asyncio
async def test_a_call_forwards_while_the_gateway_reports_itself_unready(
    gateway_url,
):
    """Over a real socket, through the real MCP path, against a gateway whose
    control plane it has never reached — `gateway_url` is unready by
    construction. Readiness reports; it does not gate."""
    async with httpx.AsyncClient() as client:
        assert (await client.get(f"{gateway_url}/ready")).status_code == 503

    async with Client(StreamableHttpTransport(url=f"{gateway_url}/mcp")) as client:
        result = await client.call_tool("track_package", {"tracking_number": "77123"})

    assert result.content[0].text == "delivered:77123"


# --- the lifecycle that keeps the report current --------------------------


@pytest.mark.asyncio
async def test_the_holder_starts_and_stops_with_the_application():
    """Both halves in one case, because each is the other's failure mode: a
    holder that is never started reports unready for ever, and one that is
    never stopped keeps polling Rail Center after the process was asked to
    shut down — holding the event loop open while uvicorn waits on it.

    `sleep` is the loop's wait, driven from here. Nothing below is timed.
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

    app = build_app(UPSTREAM, holder_serving(answer, sleep=sleep))

    async with running(app):
        assert fetches == 1, "the lifespan did not fetch on startup"
        resume.set()
        await _until(lambda: fetches == 2, "the lifespan did not start the loop")

    resume.set()
    await _settle()
    assert fetches == 2, "the refresh loop outlived the application"


@pytest.mark.asyncio
async def test_a_control_plane_that_is_down_does_not_stop_the_gateway_starting(
    caplog,
):
    """Refusing to start would turn a control plane that is briefly down into a
    gateway that never comes up. It starts, serves, says so once at WARNING —
    the difference between starting and stuck, which the one bit on `/ready`
    cannot carry — and keeps trying."""
    app = build_app(UPSTREAM, holder_serving(unreachable))

    with caplog.at_level(logging.WARNING, logger="gateway"):
        async with running(app) as client:
            assert (await client.get("/health")).status_code == 200
            assert (await client.get("/ready")).status_code == 503

    written = "\n".join(caplog.messages)
    assert "started holding no policy bundle" in written

    # And nothing in it may claim a refusal. Holding no bundle is the state the
    # contract will eventually answer by refusing, and the holder's own lines
    # said so while it had no caller — but this gateway forwards the request,
    # so an operator reading that would be hunting refusals that never
    # happened while every call went through unjudged.
    assert "refus" not in written.lower(), written


@pytest.mark.asyncio
async def test_a_gateway_that_starts_ready_says_nothing_about_it(caplog):
    """The warning above is the abnormal case and has to stay that way, or an
    operator filtering for it finds it on every healthy start too."""
    app = build_app(UPSTREAM, holder_serving(serving_a_bundle))

    with caplog.at_level(logging.WARNING, logger="gateway"):
        async with running(app) as client:
            assert (await client.get("/ready")).status_code == 200

    assert "no policy bundle" not in "\n".join(caplog.messages)


@pytest.mark.asyncio
async def test_the_first_fetch_does_not_hold_the_process_off_the_socket(
    monkeypatch, caplog
):
    """uvicorn binds nothing until the lifespan reaches its `yield`, so a first
    fetch awaited without a bound is a `/health` answering connection-refused
    for as long as the control plane is slow — up to the holder's deadline,
    which is long enough for a default Kubernetes liveness probe to kill the
    container and start the wait again. A fetch that never finishes must
    therefore not stop the start; it is left running and reported.

    The grace is shortened here rather than waited out: what is under test is
    that the wait is bounded at all, and five real seconds would say the same
    thing five hundred times slower.
    """
    monkeypatch.setattr(server, "STARTUP_FETCH_GRACE_SECONDS", 0.01)

    async def never_answers(_request) -> httpx.Response:
        await asyncio.sleep(3600)
        raise AssertionError("the fetch was meant to still be in flight")

    holder = BundleHolder(
        "http://rail-center.test",
        {},
        interval_seconds=3600,
        transport=httpx.MockTransport(never_answers),
    )

    with caplog.at_level(logging.WARNING, logger="gateway"):
        async with running(build_app(UPSTREAM, holder)) as client:
            assert (await client.get("/health")).status_code == 200
            assert (await client.get("/ready")).status_code == 503

    assert "still going" in "\n".join(caplog.messages)


@pytest.mark.asyncio
async def test_a_start_that_raises_stops_the_process_coming_up():
    """Nothing in the lifespan catches, and this is what says so. `start()`
    turns every expected failure into an outcome it returns, so a raise past it
    is a defect — and a lifespan that logged it and carried on would leave a
    gateway serving traffic, reporting itself unready for ever, and never
    retrying, because the refresh loop is created after the first fetch and a
    raise means it never was."""

    class Defective(BundleHolder):
        async def start(self):
            raise RuntimeError("a defect, not a deployment's circumstances")

    holder = Defective(
        "http://rail-center.test",
        {},
        transport=httpx.MockTransport(lambda _request: unreachable()),
    )

    with pytest.raises(RuntimeError, match="refused to start"):
        async with running(build_app(UPSTREAM, holder)):
            raise AssertionError("the app was not meant to start")


@pytest.mark.asyncio
async def test_the_unready_warning_carries_why_and_not_only_that(caplog):
    """`/ready` is one bit, so the reason is the half it cannot carry — and the
    half that separates a gateway that is starting from one that is stuck. A
    line naming only the kind sends an operator to look for a control plane
    that is down when what happened was a control plane that answered."""
    app = build_app(UPSTREAM, holder_serving(unreachable))

    with caplog.at_level(logging.WARNING, logger="gateway"):
        async with running(app):
            pass

    # This line and no other. The holder writes its own account of the same
    # failure, and it carries the reason too — so a search of the whole log
    # finds the reason whether or not the line under test still says it.
    said = [m for m in caplog.messages if m.startswith("started holding no policy")]
    assert len(said) == 1, caplog.messages
    assert "Rail Center responded 503" in said[0], said[0]


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
        async with _bundle_lifespan(holder)(None):
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
    assert 0 < server.STARTUP_FETCH_GRACE_SECONDS <= 15.0
    assert server.STARTUP_FETCH_GRACE_SECONDS < FETCH_DEADLINE_SECONDS


@pytest.mark.asyncio
async def test_a_first_fetch_that_answers_past_the_grace_still_arrives(monkeypatch):
    """`asyncio.wait` and not `wait_for`, whose timeout cancels what it waited
    on. The fetch left running past the grace is the one that creates the
    refresh loop — `start()` makes the loop after the first fetch returns — so
    cancelling it strands a gateway that is unready for ever and never retries,
    which is the one outcome `_bundle_lifespan` says the design rules out. The
    test above cannot see this: its fetch never answers at all, so a cancelled
    one and an abandoned one write the same line.

    The control plane here is slow rather than dead, which is the case that
    tells the two apart: it answers a good bundle, but only after the grace has
    already elapsed and the process has already claimed to be up.
    """
    monkeypatch.setattr(server, "STARTUP_FETCH_GRACE_SECONDS", 0.01)
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
        interval_seconds=3600,
        transport=httpx.MockTransport(answers_only_when_released),
        sleep=sleep,
    )

    async with _bundle_lifespan(holder)(None):
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
    monkeypatch.setattr(server, "STARTUP_FETCH_GRACE_SECONDS", 0.01)
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
        interval_seconds=3600,
        transport=httpx.MockTransport(lambda _request: unreachable()),
    )

    async with _bundle_lifespan(holder)(None):
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
    monkeypatch.setattr(server, "STARTUP_FETCH_GRACE_SECONDS", 0.01)
    released = asyncio.Event()

    class RaisesLate(BundleHolder):
        async def start(self):
            await released.wait()
            raise RuntimeError("a defect the grace had already elapsed on")

    holder = RaisesLate(
        "http://rail-center.test",
        {},
        interval_seconds=3600,
        transport=httpx.MockTransport(lambda _request: unreachable()),
    )

    with caplog.at_level(logging.ERROR, logger="gateway"):
        async with _bundle_lifespan(holder)(None):
            released.set()
            await _settle()

    written = "\n".join(caplog.messages)
    assert "the first policy bundle fetch raised" in written, written
    assert "a defect the grace had already elapsed on" in caplog.text
