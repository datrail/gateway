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

import asyncio
import logging

import httpx
import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

from gateway.core import lifecycle
from gateway.core.bundle.client import BundleHolder
from gateway.standalone.server import build_app
from standalone_support import (
    GATEWAY_SLUG,
    POLICY_BUNDLE,
    RAIL_CENTER,
    holder_serving,
    one_route,
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
    app = build_app(
        [one_route(UPSTREAM)],
        holder_serving(unreachable),
        plugin=True,
        rail_center=RAIL_CENTER,
    )

    async with running(app) as client:
        response = await client.get("/ready")

    assert response.status_code == 503
    assert response.json() == {"status": "not ready"}


@pytest.mark.asyncio
async def test_a_gateway_holding_a_bundle_is_ready():
    app = build_app(
        [one_route(UPSTREAM)],
        holder_serving(serving_a_bundle),
        plugin=True,
        rail_center=RAIL_CENTER,
    )

    async with running(app) as client:
        response = await client.get("/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


@pytest.mark.asyncio
async def test_the_report_does_not_carry_the_bundle_held():
    """The route is unauthenticated and shares a port with the MCP surface, so
    naming the bundle in the body is a public feed of when a customer's policy changed.
    The operator use it would serve is already served by the log line."""
    app = build_app(
        [one_route(UPSTREAM)],
        holder_serving(serving_a_bundle),
        plugin=True,
        rail_center=RAIL_CENTER,
    )

    async with running(app) as client:
        body = (await client.get("/ready")).text

    assert POLICY_BUNDLE["content_hash"] not in body


@pytest.mark.asyncio
async def test_readiness_is_read_at_the_request_and_not_cached_at_startup():
    """A gateway that started before its control plane did must become ready
    without being restarted. A verdict computed once at startup passes both
    tests above and fails this one, which is the whole reason it is here."""
    answer = unreachable
    holder = holder_serving(lambda: answer())
    app = build_app([one_route(UPSTREAM)], holder, plugin=True, rail_center=RAIL_CENTER)

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
    app = build_app([one_route(UPSTREAM)], holder, plugin=True, rail_center=RAIL_CENTER)

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
        return httpx.Response(200, json={"schema_version": "1.0", "content_hash": "v1"})

    app = build_app(
        [one_route(UPSTREAM)],
        holder_serving(missing_its_policies),
        plugin=True,
        rail_center=RAIL_CENTER,
    )

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
    app = build_app(
        [one_route(UPSTREAM)],
        holder_serving(answer),
        plugin=True,
        rail_center=RAIL_CENTER,
    )

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

    app = build_app(
        [one_route(UPSTREAM)],
        holder_serving(answer, sleep=sleep),
        plugin=True,
        rail_center=RAIL_CENTER,
    )

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
    app = build_app(
        [one_route(UPSTREAM)],
        holder_serving(unreachable),
        plugin=True,
        rail_center=RAIL_CENTER,
    )

    with caplog.at_level(logging.WARNING, logger="gateway"):
        async with running(app) as client:
            assert (await client.get("/health")).status_code == 200
            assert (await client.get("/ready")).status_code == 503

    written = "\n".join(caplog.messages)
    assert "started holding no policy bundle" in written

    # And no line *about the bundle* may claim a refusal. The holder's own lines
    # once did, describing a state it had no caller for, which left an operator
    # hunting refusals in a log that could not tell them which calls saw one.
    #
    # The mode banner is excluded because it is the one line entitled to the
    # word: it states what `enforce` does to traffic rather than reporting
    # something that happened, and what `enforce` does includes refusing a call
    # it cannot judge.
    about_the_bundle = [
        m for m in caplog.messages if not m.startswith("RAIL_PLUGIN_ENABLED=")
    ]
    assert "refus" not in "\n".join(about_the_bundle).lower(), about_the_bundle


@pytest.mark.asyncio
async def test_a_gateway_that_starts_ready_says_nothing_about_it(caplog):
    """The warning above is the abnormal case and has to stay that way, or an
    operator filtering for it finds it on every healthy start too."""
    app = build_app(
        [one_route(UPSTREAM)],
        holder_serving(serving_a_bundle),
        plugin=True,
        rail_center=RAIL_CENTER,
    )

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
    monkeypatch.setattr(lifecycle, "STARTUP_FETCH_GRACE_SECONDS", 0.01)

    async def never_answers(_request) -> httpx.Response:
        await asyncio.sleep(3600)
        raise AssertionError("the fetch was meant to still be in flight")

    holder = BundleHolder(
        "http://rail-center.test",
        {},
        GATEWAY_SLUG,
        interval_seconds=3600,
        transport=httpx.MockTransport(never_answers),
    )

    with caplog.at_level(logging.WARNING, logger="gateway"):
        async with running(
            build_app(
                [one_route(UPSTREAM)], holder, plugin=True, rail_center=RAIL_CENTER
            )
        ) as client:
            assert (await client.get("/health")).status_code == 200
            assert (await client.get("/ready")).status_code == 503

    assert "still going" in "\n".join(caplog.messages)
    assert "run for 0.01s" in "\n".join(caplog.messages)


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
        GATEWAY_SLUG,
        transport=httpx.MockTransport(lambda _request: unreachable()),
    )

    with pytest.raises(RuntimeError, match="refused to start"):
        async with running(
            build_app(
                [one_route(UPSTREAM)], holder, plugin=True, rail_center=RAIL_CENTER
            )
        ):
            raise AssertionError("the app was not meant to start")


@pytest.mark.asyncio
async def test_the_unready_warning_carries_why_and_not_only_that(caplog):
    """`/ready` is one bit, so the reason is the half it cannot carry — and the
    half that separates a gateway that is starting from one that is stuck. A
    line naming only the kind sends an operator to look for a control plane
    that is down when what happened was a control plane that answered."""
    app = build_app(
        [one_route(UPSTREAM)],
        holder_serving(unreachable),
        plugin=True,
        rail_center=RAIL_CENTER,
    )

    with caplog.at_level(logging.WARNING, logger="gateway"):
        async with running(app):
            pass

    # This line and no other. The holder writes its own account of the same
    # failure, and it carries the reason too — so a search of the whole log
    # finds the reason whether or not the line under test still says it.
    said = [m for m in caplog.messages if m.startswith("started holding no policy")]
    assert len(said) == 1, caplog.messages
    assert "Rail Center responded 503" in said[0], said[0]
