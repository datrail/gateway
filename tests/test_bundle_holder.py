"""Holding the policy bundle, and every way of failing to.

The rule under test is one sentence of the evaluation contract:

> An enforcement point that cannot reach `GET /v1/policy-bundle` has no ruleset,
> which is not the same as an empty one. It must keep serving the last bundle it
> holds, and refuse traffic if it has never held one.

An empty chain **allows**, so every case below asks the same question in a
different way: after this failure, is what is held still what was held — and
when nothing was ever held, is it still nothing? A test that only checked the
outcome's `kind` would pass on an implementation that cleared the bundle and
reported the failure honestly, which is the bug this file exists to catch.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx
import pytest

from gateway.bundle.client import (
    BUNDLE_PATH,
    DEFAULT_REFRESH_SECONDS,
    MIN_REFRESH_SECONDS,
    BundleHolder,
    refresh_seconds,
)

ONE = "5c8f1e42-0000-4000-8000-0000000000a1"
TWO = "5c8f1e42-0000-4000-8000-0000000000a2"


def bundle(version: str = "v1", *, policies: Any = None, rejected: Any = None) -> dict:
    return {
        "version": version,
        "policies": [{"id": ONE, "name": "P", "priority": 1}]
        if policies is None
        else policies,
        "bindings": [],
        "rejected": [] if rejected is None else rejected,
    }


def responder(*responses: httpx.Response | Exception):
    """A control plane that answers each request with the next thing given.

    Exhausting it is a test bug rather than a scenario, so it raises rather
    than repeating the last answer — a holder that fetched more often than the
    test expected would otherwise pass quietly.
    """
    remaining = list(responses)

    def handle(_request: httpx.Request) -> httpx.Response:
        if not remaining:
            raise AssertionError("the holder fetched more times than the test supplied")
        answer = remaining.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    return httpx.MockTransport(handle)


def holder(*responses: httpx.Response | Exception, **kwargs: Any) -> BundleHolder:
    return BundleHolder(
        "http://rail-center.test", {}, transport=responder(*responses), **kwargs
    )


# --- what is held, and what happens to it ---------------------------------


@pytest.mark.asyncio
async def test_a_first_fetch_is_held() -> None:
    h = holder(httpx.Response(200, json=bundle("v1")))
    outcome = await h.refresh()

    assert outcome.kind == "replaced"
    assert h.current() is not None
    assert h.current().version == "v1"
    assert [p.id for p in h.current().chain] == [ONE]


@pytest.mark.asyncio
async def test_nothing_is_held_before_the_first_fetch() -> None:
    """`None` means refuse, and it is the state a gateway starts in."""
    assert holder().current() is None


@pytest.mark.parametrize(
    ("label", "answer"),
    [
        ("a 503", httpx.Response(503)),
        ("a 500", httpx.Response(500)),
        ("a 404", httpx.Response(404)),
        ("a refused credential", httpx.Response(401)),
        ("a forbidden read", httpx.Response(403)),
        ("a connection failure", httpx.ConnectError("connection refused")),
        ("a timeout", httpx.ReadTimeout("timed out")),
        ("a body that is not JSON", httpx.Response(200, content=b"<html>nope</html>")),
        ("an empty body", httpx.Response(200, content=b"")),
    ],
)
@pytest.mark.asyncio
async def test_a_failed_fetch_keeps_the_bundle_already_held(
    label: str, answer: httpx.Response | Exception
) -> None:
    """The rule, from the side that matters most.

    Nine ways of not getting a bundle, and after every one the gateway is still
    enforcing the ruleset it had. An implementation that cleared the held bundle
    would report the failure just as honestly and admit every request.
    """
    h = holder(httpx.Response(200, json=bundle("v1")), answer)
    await h.refresh()

    outcome = await h.refresh()

    assert outcome.kind == "unreachable", label
    assert outcome.held == "v1", label
    assert h.current().version == "v1", label


@pytest.mark.parametrize(
    ("label", "answer"),
    [
        ("a 503", httpx.Response(503)),
        ("a refused credential", httpx.Response(401)),
        ("a connection failure", httpx.ConnectError("connection refused")),
        ("a body that is not JSON", httpx.Response(200, content=b"<html>nope</html>")),
    ],
)
@pytest.mark.asyncio
async def test_a_failed_first_fetch_holds_nothing(
    label: str, answer: httpx.Response | Exception
) -> None:
    """The other side of the same rule: nothing held means refuse.

    Not an empty bundle, which would allow — `current()` is None, and the
    caller's job is to turn that into a refusal.
    """
    h = holder(answer)
    outcome = await h.refresh()

    assert outcome.kind == "unreachable", label
    assert outcome.held is None, label
    assert h.current() is None, label


@pytest.mark.asyncio
async def test_a_bundle_that_cannot_be_applied_keeps_the_one_held() -> None:
    """Distinct from unreachable, and for a reason an operator acts on.

    `unusable` means Rail Center and this gateway have drifted, and the offending
    policy is named; `unreachable` means the network or the credential. Both keep
    what is held, and telling them apart is what decides who to page.
    """
    h = holder(
        httpx.Response(200, json=bundle("v1")),
        httpx.Response(200, json=bundle("v2", policies="not a list")),
    )
    await h.refresh()

    outcome = await h.refresh()

    assert outcome.kind == "unusable"
    assert outcome.held == "v1"
    assert h.current().version == "v1"
    assert "`policies` is not a list" in outcome.reason


@pytest.mark.asyncio
async def test_an_unusable_first_bundle_holds_nothing() -> None:
    h = holder(httpx.Response(200, json=bundle("v1", policies="not a list")))
    outcome = await h.refresh()

    assert outcome.kind == "unusable"
    assert h.current() is None


@pytest.mark.asyncio
async def test_a_new_version_replaces_what_is_held() -> None:
    h = holder(
        httpx.Response(200, json=bundle("v1")),
        httpx.Response(
            200, json=bundle("v2", policies=[{"id": TWO, "name": "Q", "priority": 9}])
        ),
    )
    await h.refresh()

    outcome = await h.refresh()

    assert outcome.kind == "replaced"
    assert h.current().version == "v2"
    assert [p.id for p in h.current().chain] == [TWO]


# --- the version short-circuit --------------------------------------------


@pytest.mark.asyncio
async def test_an_unchanged_version_is_not_reparsed() -> None:
    """Proven by sending a body that validation would refuse.

    `version` is a content hash, so an unchanged one means what is held is
    byte-for-byte what arrived and there is nothing to re-parse. The only way to
    show the short-circuit really happens is to make the un-taken path fail: the
    second answer carries the held version and a `policies` that is not a list.
    An implementation that validated first would report `unusable`.
    """
    h = holder(
        httpx.Response(200, json=bundle("v1")),
        httpx.Response(200, json=bundle("v1", policies="not a list")),
    )
    await h.refresh()

    outcome = await h.refresh()

    assert outcome.kind == "unchanged"
    assert h.current().version == "v1"


@pytest.mark.asyncio
async def test_the_short_circuit_needs_a_bundle_to_be_held() -> None:
    """A first response is validated however its version reads.

    Comparing against a held version of None would match a bundle whose version
    key is missing, and a bundle nothing validated must never be held.
    """
    h = holder(
        httpx.Response(200, json={"policies": [], "bindings": [], "rejected": []})
    )
    outcome = await h.refresh()

    assert outcome.kind == "unusable"
    assert h.current() is None


# --- what the fetch bounds ------------------------------------------------


@pytest.mark.asyncio
async def test_a_body_past_the_bound_is_refused_even_when_it_lies_about_its_length() -> (
    None
):
    """The declared length is the server's claim; the body is the fact.

    A responder that under-declares walks past the header check, so the body has
    to be measured too — and it is the only check left once the header is gone.
    """
    h = holder(
        httpx.Response(
            200,
            content=b'{"version":"v2","policies":[],"bindings":[],"rejected":[]}'
            + b" " * 4000,
            headers={"content-length": "10"},
        ),
        max_bytes=1024,
    )
    outcome = await h.refresh()

    assert outcome.kind == "unreachable"
    assert "past the 1024" in outcome.reason
    assert h.current() is None


@pytest.mark.asyncio
async def test_a_4xx_carrying_a_perfectly_good_bundle_is_still_refused() -> None:
    """The status decides, not the body.

    A control plane answering 404 with a bundle-shaped body is one that has been
    reconfigured, or one this gateway is pointed at by mistake. Reading the body
    anyway would hold a ruleset from a route that does not exist.
    """
    h = holder(
        httpx.Response(200, json=bundle("v1")),
        httpx.Response(404, json=bundle("v2")),
    )
    await h.refresh()

    outcome = await h.refresh()

    assert outcome.kind == "unreachable"
    assert "responded 404" in outcome.reason
    assert h.current().version == "v1"


@pytest.mark.asyncio
async def test_a_body_past_the_bound_is_treated_as_unreachable() -> None:
    """Refused, and the bundle held stays in force.

    The deadline bounds how long a response may take and says nothing about how
    large it may be, so a control plane answering quickly with an enormous body
    would otherwise be buffered whole before anything looked at it.
    """
    huge = bundle("v2", policies=[{"id": ONE, "name": "x" * 5000, "priority": 1}])
    h = holder(
        httpx.Response(200, json=bundle("v1")),
        httpx.Response(200, json=huge),
        max_bytes=1024,
    )
    await h.refresh()

    outcome = await h.refresh()

    assert outcome.kind == "unreachable"
    assert "past the 1024" in outcome.reason
    assert h.current().version == "v1"


@pytest.mark.asyncio
async def test_a_declared_length_past_the_bound_is_refused_before_the_body() -> None:
    """The header is read first, which is the half that avoids the memory.

    Checking only `len(response.content)` means the body is already held whole
    by the time the bound is applied — which is the thing the bound exists to
    prevent.
    """
    h = holder(
        httpx.Response(200, json=bundle("v1"), headers={"content-length": "999999"}),
        max_bytes=1024,
    )
    outcome = await h.refresh()

    assert outcome.kind == "unreachable"
    assert "declares 999999 bytes" in outcome.reason
    assert h.current() is None


# --- what an operator is told ---------------------------------------------


@pytest.mark.asyncio
async def test_a_rejected_credential_says_so_distinctly() -> None:
    """Every later refresh fails the same way until the configuration changes.

    Naming it apart from a control plane having a bad minute is what stops an
    operator waiting for it to clear.
    """
    h = holder(httpx.Response(401))
    outcome = await h.refresh()

    assert "rejected the credential (401)" in outcome.reason
    assert "RAIL_AUTH_MODE" in outcome.reason


@pytest.mark.asyncio
async def test_a_failure_is_a_warning_while_a_bundle_is_held(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """And an error once nothing is, because every request is then refused.

    The gateway with a stale ruleset is still enforcing; the gateway with none
    is not serving. Logging both at one level makes the second invisible among
    the first.
    """
    with caplog.at_level(logging.WARNING, logger="gateway.bundle"):
        cold = holder(httpx.Response(503))
        await cold.refresh()
        levels_cold = [r.levelno for r in caplog.records]

        caplog.clear()
        warm = holder(httpx.Response(200, json=bundle("v1")), httpx.Response(503))
        await warm.refresh()
        await warm.refresh()
        levels_warm = [r.levelno for r in caplog.records]

    assert logging.ERROR in levels_cold
    assert levels_warm and max(levels_warm) == logging.WARNING


@pytest.mark.asyncio
async def test_a_rejected_policy_is_named_every_time_the_bundle_changes(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """`rejected` is not an error channel to drop.

    It names what Rail Center could not compile, so a gateway that swallows it
    enforces a chain narrower than the operator wrote with nothing on either
    side saying so.
    """
    rejected = [
        {"policy_id": TWO, "policy_name": "P2", "reason": "condition not evaluable"}
    ]
    h = holder(httpx.Response(200, json=bundle("v1", rejected=rejected)))
    with caplog.at_level(logging.WARNING, logger="gateway.bundle"):
        await h.refresh()

    said = "\n".join(r.getMessage() for r in caplog.records)
    assert "P2" in said
    assert TWO in said
    assert "condition not evaluable" in said
    assert "not in force" in said


@pytest.mark.asyncio
async def test_a_reason_never_carries_a_character_a_log_line_cannot_hold() -> None:
    """A malformed response puts its own bytes in the failure's text.

    h11 quotes what it could not parse — `illegal header line: b'...'` — so a
    control plane that has been tampered with could otherwise forge a log line
    through the first failed refresh. Python's JSON decoder does not do this; it
    reports a line and column, which is why the case that reaches the guard is a
    protocol error rather than a decode error.
    """
    from gateway.key_safety import has_unsafe_key_characters

    h = holder(
        httpx.RemoteProtocolError(
            "illegal header line: b'X-Forged: real\n2026-08-29 ERROR nothing\x1b[31m'"
        )
    )
    outcome = await h.refresh()

    assert outcome.kind == "unreachable"
    assert not has_unsafe_key_characters(outcome.reason)
    assert "unprintable" in outcome.reason


# --- the request itself ---------------------------------------------------


@pytest.mark.asyncio
async def test_the_credential_and_the_route_travel_with_the_request() -> None:
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=bundle("v1"))

    h = BundleHolder(
        "http://rail-center.test/",
        {"Authorization": "Bearer t0ken"},
        transport=httpx.MockTransport(handle),
    )
    await h.refresh()

    assert str(seen[0].url) == f"http://rail-center.test{BUNDLE_PATH}"
    assert seen[0].headers["authorization"] == "Bearer t0ken"
    assert seen[0].headers["accept"] == "application/json"


@pytest.mark.parametrize(
    "configured", ["http://rc.test", "http://rc.test/", "http://rc.test///"]
)
@pytest.mark.asyncio
async def test_a_trailing_slash_does_not_double_the_path(configured: str) -> None:
    seen: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json=bundle("v1"))

    await BundleHolder(configured, {}, transport=httpx.MockTransport(handle)).refresh()

    assert seen == [f"http://rc.test{BUNDLE_PATH}"]


# --- the refresh loop -----------------------------------------------------


@pytest.mark.asyncio
async def test_start_returns_after_the_first_attempt_even_when_it_failed() -> None:
    """A gateway holding no bundle still starts, and still listens.

    It refuses every request while the loop keeps trying, which is a state an
    operator can see and act on. Refusing to start would turn a control plane
    that is briefly down into a gateway that never comes up.
    """
    ticks: list[float] = []

    async def sleep(seconds: float) -> None:
        ticks.append(seconds)
        await asyncio.sleep(0)

    h = holder(httpx.Response(503), httpx.Response(200, json=bundle("v1")), sleep=sleep)
    outcome = await h.start()
    assert outcome.kind == "unreachable"
    assert h.current() is None

    await asyncio.sleep(0)
    await asyncio.sleep(0)
    await h.stop()

    assert h.current() is not None
    assert ticks[0] == DEFAULT_REFRESH_SECONDS


@pytest.mark.asyncio
async def test_the_loop_survives_an_attempt_that_raises() -> None:
    """A loop that dies leaves the gateway enforcing what it last held, for ever.

    `_refresh_once` turns every expected failure into an outcome, so reaching
    the handler means something unforeseen — and continuing is right either way,
    because the alternative is silence after one traceback.
    """
    calls = {"n": 0}

    async def sleep(_seconds: float) -> None:
        await asyncio.sleep(0)

    h = holder(sleep=sleep)

    async def refresh_that_breaks_once():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("something unforeseen")
        from gateway.bundle.client import RefreshOutcome

        return RefreshOutcome("unreachable", None)

    h.refresh = refresh_that_breaks_once  # type: ignore[method-assign]
    h._task = asyncio.create_task(h._loop())
    for _ in range(8):
        await asyncio.sleep(0)
    await h.stop()

    assert calls["n"] > 1


@pytest.mark.asyncio
async def test_stopping_is_safe_before_starting_and_twice() -> None:
    h = holder()
    await h.stop()
    await h.stop()


# --- the interval ---------------------------------------------------------


def test_the_interval_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sixty as a literal, so the number is what is asserted.

    Written as the constant it would hold for any value of it, and the value is
    the claim: an operator is told a policy change reaches enforcement within a
    minute.
    """
    monkeypatch.delenv("RAIL_GATEWAY_BUNDLE_REFRESH_SECONDS", raising=False)
    assert DEFAULT_REFRESH_SECONDS == 60
    assert MIN_REFRESH_SECONDS == 5
    assert refresh_seconds() == 60


@pytest.mark.parametrize("value", ["5", "60", "3600", " 120 "])
def test_an_interval_at_or_above_the_floor_is_taken(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("RAIL_GATEWAY_BUNDLE_REFRESH_SECONDS", value)
    assert refresh_seconds() == int(value.strip())


@pytest.mark.parametrize("value", ["1", "0", "-30", "4"])
def test_an_interval_below_the_floor_is_raised_rather_than_refused(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    """Overruled, not fatal.

    A number that cannot be read at all is a typo and stops the process; one
    that is merely too eager is a judgement this component is entitled to
    overrule, and refusing to start over it would take enforcement down to
    protect the control plane from load.
    """
    monkeypatch.setenv("RAIL_GATEWAY_BUNDLE_REFRESH_SECONDS", value)
    assert refresh_seconds() == MIN_REFRESH_SECONDS


@pytest.mark.parametrize("value", ["sixty", "60s", "6.0", ""])
def test_an_interval_that_is_not_a_number(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("RAIL_GATEWAY_BUNDLE_REFRESH_SECONDS", value)
    if not value:
        assert refresh_seconds() == DEFAULT_REFRESH_SECONDS
        return
    with pytest.raises(RuntimeError) as caught:
        refresh_seconds()
    assert "must be an integer" in str(caught.value)
