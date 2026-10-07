"""What an enforcing gateway answers, and what it puts on the denial record.

`tests/test_evaluate.py` is about the wiring around the walk under `observe`,
where nothing the verdict says changes what the caller gets. This file is about
the half that acts: which status a refusal carries, whether a denial is reported
at all, and every field of the report when it is.

Most of that is the shared contract table, `ENFORCEMENT_CASES` in
`gateway-core/tests/core_support.py`, run here through the layer. The tests
after it are what a row cannot say: the log, the body stream and the report
budget.

**Driven as an ASGI layer rather than through a served gateway**, which is a
departure from the rest of this suite and is what the subject asks for.
`_Enforcement` sits above the MCP server and is handed raw scope and raw bytes
precisely so it can see what a parsed message has already destroyed — a repeated
header, a body that is not JSON, a disconnect arriving mid-body. A test that
went through an MCP client could not present any of those, because the client
would refuse to send them. The forwarding path stays covered where it is served
for real, in `tests/test_forwarding.py`.

The three answers this file separates, because collapsing any two of them is a
gateway that has stopped enforcing while its suite stays green:

  * **403** — judged and denied, and reported.
  * **503** — not judged at all, and reported to nobody. A 503 answered as 403
    tells a caller their ticket was rejected when the ruleset could not be
    applied, which is the confusion the contract calls the whole point of
    calling it a refusal rather than a deny.
  * **200** — forwarded, whatever the walk had to say about it under `observe`.
"""

import asyncio
import json
import logging
import time
from dataclasses import replace
from datetime import datetime
from typing import Any

import httpx
import pytest

from core_support import (
    BAD_ID,
    DENIES_EVERYTHING,
    DENIES_UNMATCHED_SKILL,
    DENY_ID,
    FULL_KEY,
    KEY,
    REASONS,
    SKILL_ID,
    UNREADABLE,
    Holder,
    build_bundle,
    build_call,
    build_policy,
    encode_ticket,
    get_enforcement_params,
)
from gateway.core.enforcement import (
    MAX_FALLBACK_REPORTS_IN_FLIGHT,
    MAX_REPORTS_IN_FLIGHT,
)
from gateway.core.key_safety import MAX_LOGGED_LENGTH
from gateway.standalone.server import _Enforcement

RAIL_CENTER_URL = "http://rail-center.test"


class _Downstream:
    """The MCP app below the layer, recording every message it was handed.

    It records rather than parses: the questions here are whether it ran at all,
    and whether what reached it is what arrived on the wire.
    """

    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []
        self.calls = 0

    async def __call__(self, scope, receive, send) -> None:
        self.calls += 1
        while True:
            message = await receive()
            self.messages.append(message)
            if message["type"] == "http.disconnect":
                return
            if not message.get("more_body"):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"forwarded"})

    @property
    def body(self) -> bytes:
        return b"".join(
            m.get("body", b"") for m in self.messages if m["type"] == "http.request"
        )


class _Reports:
    """Every denial report sent, and the answer Rail Center gave for each."""

    def __init__(self, status: int = 202, hold: asyncio.Event | None = None) -> None:
        self.status = status
        self.hold = hold
        self.bodies: list[dict[str, Any]] = []
        self.headers: list[httpx.Headers] = []

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.bodies.append(json.loads(request.content))
        self.headers.append(request.headers)
        if self.hold is not None:
            await self.hold.wait()
        return httpx.Response(self.status)

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)

    def only(self) -> dict[str, Any]:
        assert len(self.bodies) == 1, self.bodies
        return self.bodies[0]


def layer(
    held=None,
    *,
    blocking: bool = True,
    reports: _Reports | None = None,
    app: _Downstream | None = None,
) -> tuple[_Enforcement, _Downstream, _Reports]:
    """The enforcement layer over a held bundle.

    **`blocking` sets the posture on the bundle rather than on the layer**
    (RC-312). It is kept as a parameter because it is what these cases are
    about — whether a denial is acted on — but the layer no longer takes such a
    flag: it reads `enforcement.mode` off whatever is held, per request. Passing
    `blocking=False` against a bundle that was built at `enforce` would
    otherwise silently assert nothing.
    """
    if held is not None and not blocking and held.enforcement == "enforce":
        held = replace(held, enforcement="observe")
    downstream = app or _Downstream()
    recorder = reports or _Reports()
    return (
        _Enforcement(
            downstream,
            Holder(held),
            rail_center_url=RAIL_CENTER_URL,
            auth={"Authorization": "Bearer t"},
            transport=recorder.transport,
        ),
        downstream,
        recorder,
    )


class Answer:
    """What the caller got back."""

    def __init__(self, sent: list[dict[str, Any]]) -> None:
        self.sent = sent

    @property
    def status(self) -> int:
        return next(
            m["status"] for m in self.sent if m["type"] == "http.response.start"
        )

    @property
    def body(self) -> bytes:
        return b"".join(
            m.get("body", b"") for m in self.sent if m["type"] == "http.response.body"
        )

    @property
    def json(self) -> Any:
        return json.loads(self.body)


async def drive(
    enforcement,
    body: bytes = b"",
    *,
    headers: list[tuple[bytes, bytes]] | None = None,
    messages: list[dict[str, Any]] | None = None,
    method: str = "POST",
    path: str = "/mcp",
) -> Answer:
    """One request through the layer, and what came back.

    `messages` is the raw ASGI receive sequence, for the tests whose subject is
    how the body is read; everything else passes `body` and gets the ordinary
    one-chunk shape a server sends. `path` is the caller's on a real server —
    uvicorn unquotes it off the request line — so a test whose subject is what
    this layer writes about a request sets it rather than taking `/mcp`.
    """
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers if headers is not None else [],
    }
    queue = list(
        messages
        if messages is not None
        else [{"type": "http.request", "body": body, "more_body": False}]
    )

    async def receive():
        if queue:
            return queue.pop(0)
        return {"type": "http.disconnect"}

    sent: list[dict[str, Any]] = []

    async def send(message):
        sent.append(message)

    await enforcement(scope, receive, send)
    return Answer(sent)


def reported(caplog) -> list[str]:
    """Only what the reporter itself wrote.

    `caplog` captures every logger, and `judge` writes its own denial line on
    the same path — so an assertion meant for the reporter can be satisfied by
    the layer's line instead, in both directions.
    """
    return [r.message for r in caplog.records if r.name == "gateway.core.denial"]


async def settled(recorder: _Reports, *, expecting: int) -> None:
    """Let the fire-and-forget reports run before anything asserts on them.

    The layer answers the caller and returns while the report is still a task,
    which is the whole point of it being fire-and-forget. Waiting on the
    recorder rather than on the layer's own task set is deliberate: the test
    that asks whether that task set exists at all cannot use it to wait.

    The second loop runs on regardless of how many arrived, so a report a test
    says must *not* be sent has had every chance to be sent before the
    assertion that it was not.
    """
    deadline = time.monotonic() + 5.0
    while len(recorder.bodies) < expecting and time.monotonic() < deadline:
        await asyncio.sleep(0)
    for _ in range(100):
        await asyncio.sleep(0)


# --------------------------------------------------------------------------
# The contract table
# --------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("case", get_enforcement_params("standalone"))
async def test_the_answer_and_the_report_match_every_row_of_the_contract(case):
    """Each row through the layer: a refusal is answered here and never
    reaches the app below, and a forwarded call reaches it as sent."""
    enforcement, downstream, reports = layer(case.get_bundle())
    headers = [(b"x-rail", v.encode("latin-1")) for v in case.x_rail] + [
        (b"x-rail-status", v.encode("latin-1")) for v in case.x_rail_status
    ]

    answer = await drive(
        enforcement, case.body, headers=headers, method=case.method, path=case.path
    )
    await settled(reports, expecting=0 if case.report is None else 1)

    if case.status is None:
        assert answer.status == 200
        assert downstream.calls == 1
        assert downstream.body == case.body
    else:
        assert answer.status == case.status
        assert answer.json == {"error": REASONS[case.status]}
        assert downstream.calls == 0
    if case.report is None:
        assert reports.bodies == []
    else:
        body = reports.only()
        body.pop("denied_at")
        assert body == case.report


# --------------------------------------------------------------------------
# F-004 — the refusal log names the rule to disable
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_unreadable_condition_is_logged_against_the_policy_carrying_it(
    caplog,
):
    """The contract names disabling the offending policy as the remedy, which an
    operator holding two rules with the same unreadable condition cannot do from
    the field name alone. The one named is the one the walk reached — priority
    1 — because that is the rule whose removal changes the answer."""
    held = build_bundle(
        build_policy(BAD_ID, UNREADABLE, priority=1),
        build_policy(SKILL_ID, UNREADABLE, priority=2),
    )
    enforcement, _, _ = layer(held)

    with caplog.at_level(logging.ERROR, logger="gateway"):
        assert (await drive(enforcement, build_call())).status == 503

    written = "\n".join(caplog.messages)
    assert BAD_ID in written
    assert SKILL_ID not in written


# --------------------------------------------------------------------------
# F-010 — whether a denial is reported at all
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_denial_under_enforce_is_reported():
    enforcement, _, reports = layer(build_bundle(DENIES_EVERYTHING))

    await drive(enforcement, build_call())
    await settled(reports, expecting=1)

    assert len(reports.bodies) == 1
    # The credential the gateway was configured with, not the caller's. A report
    # is this gateway speaking to Rail Center as itself.
    assert reports.headers[0]["Authorization"] == "Bearer t"


# --------------------------------------------------------------------------
# F-009 — every field of the report the contract table does not pin
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_denied_at_is_an_absolute_instant():
    """A naive local time shifts every denial by the host's UTC offset, and a
    denial's time is what an operator correlates everything else against."""
    enforcement, _, reports = layer(build_bundle(DENIES_EVERYTHING))

    await drive(enforcement, build_call())
    await settled(reports, expecting=1)

    denied_at = datetime.fromisoformat(reports.only()["denied_at"])
    assert denied_at.tzinfo is not None
    assert denied_at.utcoffset().total_seconds() == 0


# --------------------------------------------------------------------------
# F-011 — what happens when the report does not land
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_report_rail_center_refuses_is_named_in_the_log(caplog):
    """The only signal that this gateway and Rail Center disagree about the
    shape of a denial. A 422 swallowed as success is a missing row and a silent
    schema drift, which is the failure this whole path exists to make visible."""
    reports = _Reports(status=422)
    enforcement, _, _ = layer(build_bundle(DENIES_EVERYTHING), reports=reports)

    with caplog.at_level(logging.WARNING, logger="gateway"):
        await drive(enforcement, build_call())
        await settled(reports, expecting=1)

    # The reporter's own lines. `caplog` captures every logger, and the
    # enforcement layer writes its own denial line on this same path — reading
    # both together would let that one satisfy an assertion about this one.
    written = "\n".join(reported(caplog))
    assert "422" in written
    assert DENY_ID in written
    assert KEY in written, "the line names the denial, not only the rule"


@pytest.mark.asyncio
async def test_a_report_that_never_left_names_the_denial_it_describes(caplog):
    """A fallback refusal carries no `policy_id`, so a line identified by the
    rule alone identifies nothing at all — and sends an operator chasing a
    policy that does not exist. The endpoint key is what the whole class of
    refusals reached without a rule has, and it is what an operator reading a
    gap in the denials table is holding."""

    def unreachable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    enforcement = _Enforcement(
        _Downstream(),
        Holder(build_bundle(fallback="block")),
        rail_center_url=RAIL_CENTER_URL,
        auth={"Authorization": "Bearer t"},
        transport=httpx.MockTransport(unreachable),
    )

    with caplog.at_level(logging.WARNING, logger="gateway"):
        assert (await drive(enforcement, build_call())).status == 403
        for _ in range(200):
            await asyncio.sleep(0)

    written = "\n".join(reported(caplog))
    assert "ConnectError" in written
    assert KEY in written


@pytest.mark.asyncio
async def test_an_accepted_report_says_nothing(caplog):
    """The counterpart, so the test above is about the status and not about the
    path always logging."""
    reports = _Reports(status=202)
    enforcement, _, _ = layer(build_bundle(DENIES_EVERYTHING), reports=reports)

    with caplog.at_level(logging.WARNING, logger="gateway"):
        await drive(enforcement, build_call())
        await settled(reports, expecting=1)

    assert reported(caplog) == []


@pytest.mark.asyncio
async def test_a_report_is_bounded_in_time(monkeypatch):
    """Nothing waits on a report, so a slow control plane must cost a dropped
    row rather than a task outliving the request it describes by a minute.

    The bound is read off the client the reporter builds rather than off the
    constant, because the constant proves nothing if it stops being passed —
    and the value itself is deliberately not asserted, so tuning it is not a
    test failure."""
    seen: list[Any] = []
    real = httpx.AsyncClient

    def recording(*args, **kwargs):
        seen.append(kwargs.get("timeout"))
        return real(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", recording)
    enforcement, _, reports = layer(build_bundle(DENIES_EVERYTHING))

    await drive(enforcement, build_call())
    await settled(reports, expecting=1)

    assert seen, "the reporter built no client"
    assert all(isinstance(t, (int, float)) and 0 < t < 60 for t in seen), seen


@pytest.mark.asyncio
async def test_a_report_in_flight_is_held_by_a_strong_reference():
    """`asyncio.create_task` is only weakly held by the loop, so a report with
    nothing else referencing it can be collected mid-flight and simply never
    arrive — a missing row with nothing in the log to say why.

    Both halves are asserted, because they fail in opposite directions: without
    the reference the set is empty while the report is still in flight, and
    without the done callback it never empties and the layer leaks a task per
    denial for the life of the process."""
    hold = asyncio.Event()
    reports = _Reports(hold=hold)
    enforcement, _, _ = layer(build_bundle(DENIES_EVERYTHING), reports=reports)

    await drive(enforcement, build_call())
    for _ in range(50):
        await asyncio.sleep(0)

    assert len(enforcement._reporter._reports) == 1
    assert not next(iter(enforcement._reporter._reports)).done()

    hold.set()
    await settled(reports, expecting=1)

    assert enforcement._reporter._reports == set()


@pytest.mark.asyncio
async def test_a_walk_that_raises_forwards_rather_than_refusing(caplog, monkeypatch):
    """A defect in the walk must not take the forward path down. The trade is
    stated in `judge` and is the same one `_UpstreamErrorBoundary` makes — a
    gateway that forwards nothing is worse than one that enforces nothing — and
    turning this into a 503 reverses it, so an unforeseen bug becomes a total
    outage rather than a logged traceback."""

    exploded: list[bool] = []

    def explode(*_args, **_kwargs):
        exploded.append(True)
        raise RuntimeError("a defect in the walk")

    monkeypatch.setattr("gateway.core.enforcement.decide", explode)
    enforcement, downstream, reports = layer(build_bundle(DENIES_EVERYTHING))

    with caplog.at_level(logging.ERROR, logger="gateway"):
        answer = await drive(enforcement, build_call())
    await settled(reports, expecting=0)

    assert answer.status == 200
    assert downstream.calls == 1
    assert reports.bodies == []
    assert "a defect in the walk" in caplog.text
    assert exploded


# --------------------------------------------------------------------------
# PTH.G1 — `fallback`: what happens to a call no binding matches
# --------------------------------------------------------------------------
#
# The half of RC-312 that changes what a caller gets. `enforcement.mode` decides
# whether a verdict is acted on; `fallback` decides whether an endpoint nobody
# bound reaches the chain at all. The contract composes the two additively, most
# restrictive first, and scopes that to fallback-against-chain only — so `block`
# refuses without walking, and `pass` is *not refused for being unbound* rather
# than unjudged.
#
# Every case here calls an endpoint the bundle carries no binding for, which is
# the only state the fallback speaks to.


@pytest.mark.asyncio
async def test_an_enforcing_gateway_refuses_without_previewing_the_same_call(caplog):
    """The log tells a preview from a refusal, and one call earns one of them.

    `observe` says what `block` would refuse and `enforce` refuses it — the
    posture is the whole of the difference, and the log is the only place an
    operator can see which one they are running. A gateway writing both for one
    request puts "this mode enforces nothing, so it was forwarded" directly
    above the line recording that it was refused, which is a false statement
    about the request beside a true one.
    """
    enforcement, downstream, _ = layer(build_bundle(fallback="block"))

    with caplog.at_level(logging.INFO, logger="gateway"):
        answer = await drive(
            enforcement, build_call(), headers=[(b"x-rail", encode_ticket().encode())]
        )

    assert answer.status == 403
    assert downstream.calls == 0
    written = "\n".join(caplog.messages)
    assert "denied" in written and "fallback=block" in written
    assert "would deny" not in written


@pytest.mark.asyncio
async def test_reports_past_the_fallback_cap_are_shed_rather_than_queued(caplog):
    """The fallback refusal is the one reachable with nothing in hand.

    It needs no ticket, no tool name this gateway recognises and no binding, so
    arbitrary bytes produce one bearer-authenticated POST to Rail Center each —
    and an uncapped task set turns a caller's request rate into Rail Center's
    ingest rate and into this gateway's socket count. Shedding costs the record
    and not the enforcement — nothing the 403 is built from is read back out of
    a report — so the 403 is unchanged and nothing is forwarded.

    This class is capped below the whole budget, which is what the assertion
    reads: `MAX_FALLBACK_REPORTS_IN_FLIGHT` arrive, not `MAX_REPORTS_IN_FLIGHT`.
    """
    held = asyncio.Event()
    reports = _Reports(hold=held)
    enforcement, downstream, _ = layer(build_bundle(fallback="block"), reports=reports)

    with caplog.at_level(logging.WARNING, logger="gateway"):
        for n in range(MAX_REPORTS_IN_FLIGHT + 10):
            answer = await drive(enforcement, b"not json at all %d" % n)
            assert answer.status == 403, n
        for _ in range(500):
            await asyncio.sleep(0)

        assert len(reports.bodies) == MAX_FALLBACK_REPORTS_IN_FLIGHT
        assert any("already in flight" in m for m in caplog.messages)

    assert downstream.calls == 0
    held.set()
    await settled(reports, expecting=MAX_FALLBACK_REPORTS_IN_FLIGHT)


@pytest.mark.asyncio
async def test_a_rule_decided_denial_is_reported_with_the_unruled_class_full():
    """The budget is reserved by class, so the cheap class cannot evict the other.

    One shared budget shed first-come makes the reports reachable with nothing
    in hand — no ticket, no tool name, no binding — a lever over the reports
    that carry a verdict: hold the set full and every rule-decided denial is
    absent from Rail Center's record, including the attacker's own once it
    starts sending well-formed calls. A Rail Center slow enough to hold the
    tasks open produces the same loss with nobody meaning to.

    So: fill the policy-less class past its sub-cap with unparseable bytes while
    Rail Center holds every report open, then deny a call by a rule that
    matched. The denial that names a policy is still reported.
    """
    bound_to_the_denying_rule = {
        "endpoint_key": FULL_KEY,
        "mode": "gated",
        "policy_ids": [DENY_ID],
    }
    held = asyncio.Event()
    reports = _Reports(hold=held)
    enforcement, downstream, _ = layer(
        build_bundle(
            DENIES_EVERYTHING,
            bindings=[bound_to_the_denying_rule],
            fallback="block",
        ),
        reports=reports,
    )

    for n in range(MAX_FALLBACK_REPORTS_IN_FLIGHT + 10):
        assert (await drive(enforcement, b"not json at all %d" % n)).status == 403, n
    for _ in range(500):
        await asyncio.sleep(0)
    assert len(reports.bodies) == MAX_FALLBACK_REPORTS_IN_FLIGHT
    assert all("policy_id" not in body for body in reports.bodies)

    assert (await drive(enforcement, build_call())).status == 403

    await settled(reports, expecting=MAX_FALLBACK_REPORTS_IN_FLIGHT + 1)
    assert len(reports.bodies) == MAX_FALLBACK_REPORTS_IN_FLIGHT + 1
    assert reports.bodies[-1]["policy_id"] == DENY_ID

    assert downstream.calls == 0
    held.set()


@pytest.mark.asyncio
async def test_reports_past_the_total_cap_are_shed_whatever_decided_them():
    """The total bounds every report, including the ones a rule decided.

    The sub-cap holds only the policy-less class, so nothing it does limits how
    many bearer-authenticated POSTs to Rail Center a caller who can reach one
    denying rule holds open at once — those name a policy and are counted
    against the total alone. A Rail Center slow enough to hold each report open
    is what makes the difference visible: the reports accumulate, and the total
    is the only thing that stops them.
    """
    held = asyncio.Event()
    reports = _Reports(hold=held)
    enforcement, downstream, _ = layer(build_bundle(DENIES_EVERYTHING), reports=reports)

    for n in range(MAX_REPORTS_IN_FLIGHT + 10):
        assert (await drive(enforcement, build_call())).status == 403, n
    for _ in range(500):
        await asyncio.sleep(0)

    assert len(reports.bodies) == MAX_REPORTS_IN_FLIGHT
    # Every one of them names the rule that denied it, so the sub-cap on the
    # policy-less class is not what shed the rest.
    assert all(body["policy_id"] == DENY_ID for body in reports.bodies)

    assert downstream.calls == 0
    held.set()
    await settled(reports, expecting=MAX_REPORTS_IN_FLIGHT)


@pytest.mark.asyncio
async def test_the_policy_less_class_frees_its_budget_as_each_report_lands():
    """The sub-cap bounds what is in flight, not what a process may ever send.

    A report leaves the policy-less set when its task finishes, so a gateway
    that has already sent `MAX_FALLBACK_REPORTS_IN_FLIGHT` fallback reports and
    seen every one of them land reports the next one too. A set that never
    drained would make the sub-cap a lifetime limit instead: past the
    sixteenth, every refusal of an endpoint nobody bound is answered 403 and
    absent from Rail Center for the life of the process — silently, since the
    caller is refused either way, and permanently rather than for as long as
    the set stays full.

    So: no hold, and `settled` between the two halves, which is what makes this
    a drained set rather than a full one.
    """
    reports = _Reports()
    enforcement, downstream, _ = layer(build_bundle(fallback="block"), reports=reports)

    for n in range(MAX_FALLBACK_REPORTS_IN_FLIGHT):
        assert (await drive(enforcement, b"not json at all %d" % n)).status == 403, n
    await settled(reports, expecting=MAX_FALLBACK_REPORTS_IN_FLIGHT)
    assert len(reports.bodies) == MAX_FALLBACK_REPORTS_IN_FLIGHT

    assert (await drive(enforcement, b"one more that nothing bound")).status == 403

    await settled(reports, expecting=MAX_FALLBACK_REPORTS_IN_FLIGHT + 1)
    assert len(reports.bodies) == MAX_FALLBACK_REPORTS_IN_FLIGHT + 1
    assert "policy_id" not in reports.bodies[-1]

    assert downstream.calls == 0


@pytest.mark.asyncio
async def test_the_fallback_refusal_says_in_the_log_what_the_caller_is_not_told(
    caplog,
):
    """The operator's half of the same trade: the log distinguishes what the
    403 deliberately does not, and says that nothing was reported, so a denial
    absent from Rail Center is not read as a request that was never refused."""
    enforcement, _, _ = layer(build_bundle(fallback="block"))

    with caplog.at_level(logging.WARNING, logger="gateway"):
        await drive(enforcement, build_call())

    written = "\n".join(caplog.messages)
    assert KEY in written
    assert "fallback=block" in written
    # The refusal *is* reported — what the caller is not told is which
    # endpoint has no binding, and the log is where that lives.
    assert "no policy judged it" in written


# --------------------------------------------------------------------------
# F-005 — reading the body without swallowing a disconnect
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_body_arriving_in_chunks_reaches_the_app_below_intact():
    enforcement, downstream, _ = layer(build_bundle(DENIES_EVERYTHING), blocking=False)
    whole = build_call()
    chunks = [whole[:10], whole[10:25], whole[25:]]

    answer = await drive(
        enforcement,
        messages=[
            {"type": "http.request", "body": c, "more_body": i < len(chunks) - 1}
            for i, c in enumerate(chunks)
        ],
    )

    assert answer.status == 200
    assert downstream.body == whole


@pytest.mark.asyncio
async def test_a_disconnect_is_not_the_end_of_a_body():
    """`http.disconnect` carries neither `body` nor `more_body`, so reading it as
    the last chunk ends the drain on a body that never finished arriving — and
    then hands that fragment downstream as a complete request while swallowing
    the one message telling the app below the caller is gone."""
    enforcement, downstream, _ = layer(build_bundle(DENIES_EVERYTHING), blocking=False)
    whole = build_call()

    await drive(
        enforcement,
        messages=[
            {"type": "http.request", "body": whole[:20], "more_body": True},
            {"type": "http.disconnect"},
        ],
    )

    assert [m["type"] for m in downstream.messages] == [
        "http.request",
        "http.disconnect",
    ]
    # The fragment is presented as the fragment it is, never as a whole body.
    assert downstream.messages[0]["body"] == whole[:20]
    assert downstream.messages[0]["more_body"] is True


# --------------------------------------------------------------------------
# F-027 — a body that never finished arriving is not a call
# --------------------------------------------------------------------------

#: `/mcp#tools/call#track_package` exempt from every rule in the chain — `open`
#: narrows to nothing. It is what makes the two halves below differ: the same
#: agent, the same bytes, and a verdict that turns on whether the body finished.
EXEMPT = [{"endpoint_key": FULL_KEY, "mode": "open", "policy_ids": []}]


@pytest.mark.asyncio
async def test_a_call_aborted_mid_body_is_not_judged_and_reports_no_denial(caplog):
    """A fragment does not parse, so it resolves `unrecognised` and faces the
    whole chain — while the call it is a fragment of is bound `open` and exempt
    from every rule in it. Judging it therefore records a policy denial against
    a named agent on a call the ruleset allows, and Rail Center takes that
    attribution as given rather than re-deriving it. Nothing is answered because
    a body ends short only when the caller has already gone, and uvicorn drops
    whatever the layer composes after that: the forged row is the whole of the
    damage, and the log line is the whole of the operator's signal."""
    held = build_bundle(DENIES_UNMATCHED_SKILL, bindings=EXEMPT)
    whole = build_call()
    carrying = [(b"x-rail", encode_ticket(posture_score=90).encode())]

    enforcement, _, reports = layer(held)
    complete = await drive(enforcement, whole, headers=carrying)
    await settled(reports, expecting=0)
    assert complete.status == 200
    assert reports.bodies == []

    enforcement, downstream, reports = layer(held)
    with caplog.at_level(logging.INFO, logger="gateway"):
        answer = await drive(
            enforcement,
            headers=carrying,
            messages=[
                {"type": "http.request", "body": whole[:20], "more_body": True},
                {"type": "http.disconnect"},
            ],
        )
    await settled(reports, expecting=0)

    assert reports.bodies == []
    assert answer.sent == []
    assert any("abandoned before its body" in m for m in caplog.messages)
    # F-005's half still holds: the abort reaches the app below as an abort.
    assert [m["type"] for m in downstream.messages] == [
        "http.request",
        "http.disconnect",
    ]


@pytest.mark.asyncio
async def test_an_abort_before_a_single_body_byte_reports_nothing_either():
    """No body byte is needed to produce a forged row: headers and a
    `content-length` are enough, and the empty fragment resolves `unrecognised`
    exactly as a partial one does."""
    enforcement, downstream, reports = layer(build_bundle(DENIES_UNMATCHED_SKILL))

    answer = await drive(
        enforcement,
        headers=[(b"x-rail", encode_ticket().encode()), (b"content-length", b"900")],
        messages=[{"type": "http.disconnect"}],
    )
    await settled(reports, expecting=0)

    assert reports.bodies == []
    assert answer.sent == []
    assert [m["type"] for m in downstream.messages] == ["http.disconnect"]


@pytest.mark.asyncio
async def test_the_abandoned_path_is_rendered_before_it_reaches_the_log(caplog):
    """The path in that line is the caller's. uvicorn sets `scope["path"]` from
    the unquoted raw path, and an abort needs neither a ticket nor a body byte —
    so a `POST /mcp%0a…%1b%5b31m` arrives here carrying a newline, a line in the
    exact format `judge` writes a real denial in, and a live ANSI escape aimed
    at whatever renders the log. Unrendered, the one signal an operator has that
    a call was abandoned is also the one place an unauthenticated caller can
    forge the denial they would go looking for. Refused whole rather than
    escaped, and bounded: past `MAX_LOGGED_LENGTH` a path is a payload."""
    forged = (
        "/mcp\n2026-08-30 12:00:00 WARNING gateway"
        " denied delivery.track_package by policy FORGED\x1b[31m"
    )
    overlong = "/" + "a" * 4000
    tail = "abandoned before its body finished arriving; not judged"

    with caplog.at_level(logging.INFO, logger="gateway"):
        for path in (forged, overlong):
            enforcement, _, reports = layer(build_bundle(DENIES_EVERYTHING))
            answer = await drive(
                enforcement,
                path=path,
                headers=[(b"content-length", b"900")],
                messages=[{"type": "http.disconnect"}],
            )
            await settled(reports, expecting=0)
            assert answer.sent == []

    assert [m for m in caplog.messages if tail in m] == [
        f"<unprintable> {tail}",
        f"/{'a' * (MAX_LOGGED_LENGTH - 1)}…<truncated> {tail}",
    ]


# --- what observe says about the fallback ---------------------------------


@pytest.mark.asyncio
async def test_observe_says_what_block_would_refuse_and_still_walks(caplog) -> None:
    """The rung that previews enforcement must preview the fallback too.

    An operator has to see what `block` would refuse *before* it refuses
    anything, which is the whole of what `observe` is for — and the design's
    case for making `observe` unskippable rests on it. But saying it is the
    whole of what this posture does: acting on it here would mean refusing
    without the chain being consulted, which is `enforce`'s behaviour, so the
    walk still runs and the verdict is still logged beside the warning.
    """
    enforcement, _, reports = layer(
        build_bundle(DENIES_EVERYTHING, fallback="block"), blocking=False
    )

    # Captured at WARNING, which `RAIL_GATEWAY_LOG_LEVEL` accepts: the preview
    # an operator reads before turning `block` on has to survive the level they
    # are most likely to run, and the policy preview beside it already does.
    with caplog.at_level(logging.WARNING, logger="gateway"):
        answer = await drive(enforcement, build_call())

    assert answer.status == 200, "observe acts on nothing, the fallback included"
    written = "\n".join(caplog.messages)
    assert "would deny" in written and "fallback=block" in written
    assert "would deny" in written and DENY_ID in written, (
        "the chain was walked as well, so its verdict is in the log too"
    )
    await settled(reports, expecting=0)
    assert reports.bodies == [], "a report is an action, and observe takes none"
