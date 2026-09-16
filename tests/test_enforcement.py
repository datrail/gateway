"""What an enforcing gateway answers, and what it puts on the denial record.

`tests/test_evaluate.py` is about the wiring around the walk under `observe`,
where nothing the verdict says changes what the caller gets. This file is about
the half that acts: which status a refusal carries, whether a denial is reported
at all, and every field of the report when it is.

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

from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
from dataclasses import replace
from datetime import datetime
from typing import Any

import httpx
import pytest

from gateway.bundle.validate import validate_bundle
from gateway.endpoint import MAX_BODY_NESTING_DEPTH
from gateway.key_safety import MAX_LOGGED_LENGTH
from gateway.server import (
    MAX_FALLBACK_REPORTS_IN_FLIGHT,
    MAX_REPORTS_IN_FLIGHT,
    _Enforcement,
)

SLUG = "delivery"
KEY = "/mcp#tools/call#track_package"
RAIL_CENTER_URL = "http://rail-center.test"

DENY_ID = "5c8f1e42-0000-4000-8000-0000000000d1"
SKILL_ID = "5c8f1e42-0000-4000-8000-0000000000d2"
BAD_ID = "5c8f1e42-0000-4000-8000-0000000000e1"

#: The literal Rail Center matches on, spelled out rather than imported. A test
#: that reads the key through `denial.REPORTED_STATUS_KEY` passes just as
#: happily when the constant is renamed, and the constant *is* the wire format —
#: a verdict under any other name leaves the operator-facing column blank.
WIRE_STATUS_KEY = "x-rail-status"
WIRE_CLAIMED_KEY = "claimed-x-rail-status"


def policy(pid: str, condition: dict[str, Any], *, priority: int = 1, action="block"):
    return {
        "id": pid,
        "name": f"policy {pid[-2:]}",
        "priority": priority,
        "condition": condition,
        "action": action,
        "enabled": True,
    }


def bundle(
    *policies: dict[str, Any],
    bindings: list[dict[str, Any]] | None = None,
    enforcement: str = "enforce",
    fallback: str = "pass",
):
    """A validated bundle, at `enforce`/`pass` unless a case asks otherwise.

    The posture is part of the bundle after RC-312 rather than a flag on the
    layer that reads it, which is why it is a parameter here: a case that wants
    a verdict logged and not acted on asks for an `observe` bundle, the same way
    an operator would.

    **The fallback default is `pass` and Rail Center's is `block`**, which is a
    deliberate disagreement rather than an oversight. Almost every case here is
    about the walk — which policy denied, what the report names, what the caller
    is told — and every one of them calls an endpoint with no binding entry,
    because a binding is not what any of them is testing. Under `block` the
    fallback would refuse each of those before the chain was reached, and the
    file would pass while asserting nothing about the walk at all. The cases
    that *are* about the fallback name it.
    """
    return validate_bundle(
        {
            "schema_version": "1.0",
            "content_hash": "v-enforce",
            "policies": list(policies),
            "bindings": bindings or [],
            "enforcement": {"mode": enforcement},
            "binding_fallback": fallback,
        }
    )


#: The seeded "deny unknown agents": it holds on any request arriving without a
#: ticket, which is every request below that does not deliberately carry one.
#: One rule in the chain, so the policy a report names is never ambiguous.
DENIES_EVERYTHING = policy(DENY_ID, {"field": "x_rail_header", "operator": "missing"})

#: Denies a request that *does* carry a ticket, for the handful of cases whose
#: subject is what the claims on one become in a report. It keys on the presence
#: of `agent_id` rather than on the claim's value, so a test can send a malformed
#: claim and still reach the denial the malformed claim is about.
DENIES_ANY_TICKET = policy(DENY_ID, {"field": "agent_id", "operator": "present"})

#: Keyed on the endpoint, so it leaves the chain for a message that names no
#: tool by design and stays in it for one this gateway could not resolve.
DENIES_UNMATCHED_SKILL = policy(
    SKILL_ID, {"field": "skill_match", "operator": "missing"}
)

#: Outside the grammar. Two of these at different priorities is what asks
#: whether a refusal names the rule an operator has to disable.
UNREADABLE = {"field": "invented_field", "operator": "eq", "value": 1}


class _Holder:
    """A bundle holder that holds what the test said, and nothing else.

    `_Enforcement` asks it one question — `current()` — so standing up a real
    `BundleHolder` and a control plane for it would be a fetch, a refresh loop
    and a transport in service of a single return value.
    """

    def __init__(self, held=None):
        self.held = held

    def current(self):
        return self.held


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


def ticket(**claims: Any) -> str:
    """An `x-rail` header carrying `claims`, unpadded as the mint emits it."""
    claims.setdefault("agent_id", "5c8f1e42-0000-4000-8000-00000000a9e7")
    claims.setdefault("exp", 4102444800)  # 2100-01-01, comfortably unexpired
    raw = json.dumps(claims).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def call(tool: str = "track_package") -> bytes:
    return json.dumps({"method": "tools/call", "params": {"name": tool}}).encode()


KEYLESS = json.dumps({"method": "resources/read"}).encode()
DISCOVERY = tuple(
    json.dumps({"method": m}).encode()
    for m in ("initialize", "notifications/initialized", "tools/list")
)


def deep_call(depth: int) -> bytes:
    """A `tools/call` nesting `depth` levels — a kilobyte of brackets, no more."""
    inner = "[" * (depth - 3) + "]" * (depth - 3)
    return (
        '{"method": "tools/call", "params": {"name": "track_package", '
        f'"arguments": {{"q": {inner}}}}}}}'
    ).encode()


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
            _Holder(held),
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

    `caplog` captures every logger, and `_judge` writes its own denial line on
    the same path — so an assertion meant for the reporter can be satisfied by
    the layer's line instead, in both directions.
    """
    return [r.message for r in caplog.records if r.name == "gateway.denial"]


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
# F-008 — the status an enforcing gateway answers with
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_denied_call_is_refused_with_403_and_never_forwarded():
    """The branch's whole reason for existing. Answering 200 here — the caller
    let through with the verdict computed, logged and discarded — is a gateway
    that has stopped enforcing while every other test still passes."""
    enforcement, downstream, _ = layer(bundle(DENIES_EVERYTHING))

    answer = await drive(enforcement, call())

    assert answer.status == 403
    assert downstream.calls == 0


@pytest.mark.asyncio
async def test_a_call_that_could_not_be_judged_is_refused_with_503_not_403():
    """503 and 403 are different answers and must not collapse into one.

    A 403 tells the caller their ticket was judged and rejected. This one was
    not judged at all: it reached a rule outside this build's grammar, under a
    posture that says refuse. Answering 403 would say a policy decided something
    when none did.

    **The other half of this pair moved in RC-312** and is
    `test_a_gateway_holding_no_bundle_forwards_because_it_has_been_told_no_posture`
    below. Holding no bundle used to be refused here too, against a posture read
    from the environment at start-up; the posture now arrives *in* the bundle,
    so a gateway holding none has not been told to enforce.
    """
    undecidable, _, _ = layer(bundle(policy(BAD_ID, UNREADABLE)))
    assert (await drive(undecidable, call())).status == 503


@pytest.mark.asyncio
async def test_a_gateway_holding_no_bundle_forwards_because_it_has_been_told_no_posture():
    """The half RC-312 inverted, and the one worth stating the reason for.

    Refusing here would enforce a decision no operator made: the posture lives in
    the bundle, so a gateway holding none has been told nothing rather than told
    to refuse. What keeps traffic off a gateway in this state is `/ready`, which
    answers 503 until a bundle arrives — a report an orchestrator acts on, rather
    than a refusal the caller sees.

    It is also what makes the first poll safe. Under the old rule a gateway
    starting up refused every call until its first fetch landed, so a control
    plane that was briefly slow was an outage of the protected service.
    """
    no_bundle, downstream, reports = layer(None)

    answer = await drive(no_bundle, call())

    assert answer.status == 200
    assert downstream.calls == 1
    # Nothing was judged, so nothing may be reported as judged.
    await settled(reports, expecting=0)
    assert reports.bodies == []


@pytest.mark.asyncio
async def test_neither_refusal_reaches_the_app_below():
    """A refusal is answered *for* the upstream, so the upstream never sees it.

    Two refusals, not three: holding no bundle stopped being one in RC-312, and
    that case is asserted from the other side above — it forwards, and the
    upstream *does* see it.
    """
    for held in (bundle(policy(BAD_ID, UNREADABLE)), bundle(DENIES_EVERYTHING)):
        enforcement, downstream, _ = layer(held)
        await drive(enforcement, call())
        assert downstream.calls == 0


@pytest.mark.asyncio
async def test_observe_forwards_every_one_of_them():
    """The same three cases under the mode that blocks nothing. This is what
    makes the assertions above about `enforce` rather than about the walk."""
    for held in (None, bundle(policy(BAD_ID, UNREADABLE)), bundle(DENIES_EVERYTHING)):
        enforcement, downstream, _ = layer(held, blocking=False)
        answer = await drive(enforcement, call())
        assert answer.status == 200
        assert downstream.calls == 1


# --------------------------------------------------------------------------
# F-006 — what the refusal tells the caller
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_403_does_not_name_the_policy_that_denied():
    """The ticket is unsigned and this gateway is the only thing in front of the
    upstream, so a caller told which id stopped each attempt can vary its claims
    and binary-search the tenant's chain. The operator's copy is on the trusted
    side: the log line names it, and so does the report."""
    enforcement, _, reports = layer(bundle(DENIES_EVERYTHING))

    answer = await drive(enforcement, call())
    await settled(reports, expecting=1)

    assert DENY_ID not in answer.body.decode()
    assert answer.json == {"error": "denied by policy"}
    assert reports.only()["policy_id"] == DENY_ID


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
    held = bundle(
        policy(BAD_ID, UNREADABLE, priority=1),
        policy(SKILL_ID, UNREADABLE, priority=2),
    )
    enforcement, _, _ = layer(held)

    with caplog.at_level(logging.ERROR, logger="gateway"):
        assert (await drive(enforcement, call())).status == 503

    written = "\n".join(caplog.messages)
    assert BAD_ID in written
    assert SKILL_ID not in written


# --------------------------------------------------------------------------
# F-010 — whether a denial is reported at all
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_denial_under_enforce_is_reported():
    enforcement, _, reports = layer(bundle(DENIES_EVERYTHING))

    await drive(enforcement, call())
    await settled(reports, expecting=1)

    assert len(reports.bodies) == 1
    # The credential the gateway was configured with, not the caller's. A report
    # is this gateway speaking to Rail Center as itself.
    assert reports.headers[0]["Authorization"] == "Bearer t"


@pytest.mark.asyncio
async def test_observe_reports_nothing_it_would_have_denied():
    """A denial table filled from a mode that blocks nothing leaves an operator
    unable to tell which rows stopped traffic. The verdict is still reached and
    still logged — the request is forwarded and no row is written."""
    enforcement, downstream, reports = layer(bundle(DENIES_EVERYTHING), blocking=False)

    answer = await drive(enforcement, call())
    await settled(reports, expecting=0)

    assert answer.status == 200
    assert downstream.calls == 1
    assert reports.bodies == []


@pytest.mark.asyncio
async def test_a_refusal_reports_nothing_because_no_policy_decided():
    """503, not 403, and therefore no row: naming a policy on a request the
    ruleset could not be applied to attributes a verdict nobody reached.

    The no-bundle case moved in RC-312 — it answers 200 now — but the half this
    is about did not: whatever the status, a call no policy decided reports
    nothing. Both are asserted, from their own sides.
    """
    enforcement, _, reports = layer(bundle(policy(BAD_ID, UNREADABLE)))
    assert (await drive(enforcement, call())).status == 503
    await settled(reports, expecting=0)
    assert reports.bodies == []


@pytest.mark.asyncio
async def test_an_allowed_call_reports_nothing():
    enforcement, downstream, reports = layer(bundle(DENIES_EVERYTHING))

    answer = await drive(
        enforcement, call(), headers=[(b"x-rail", ticket(posture_score=90).encode())]
    )
    await settled(reports, expecting=0)

    assert answer.status == 200
    assert downstream.calls == 1
    assert reports.bodies == []


# --------------------------------------------------------------------------
# F-009 — every field of the report
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_report_names_the_endpoint_and_the_policy_and_no_data_source():
    enforcement, _, reports = layer(bundle(DENIES_EVERYTHING))

    await drive(enforcement, call())
    await settled(reports, expecting=1)
    body = reports.only()

    assert body["policy_id"] == DENY_ID
    assert body["endpoint_key"] == KEY
    # Verbatim. Rail Center resolves the data source by this string, so a
    # gateway that folds its case names one nothing is registered under.
    # **No data source is named, and that is the report's shape now.** This
    # gateway fronts several and composes a key with no slug in it, so naming
    # one would assert a value it does not hold; the receiver resolves the data
    # source from the reporting gateway and the key.
    assert "datasource_slug" not in body
    assert "datasource_id" not in body
    assert body["metadata"]["endpoint_resolution"] == "resolved"


@pytest.mark.asyncio
async def test_denied_at_is_an_absolute_instant():
    """A naive local time shifts every denial by the host's UTC offset, and a
    denial's time is what an operator correlates everything else against."""
    enforcement, _, reports = layer(bundle(DENIES_EVERYTHING))

    await drive(enforcement, call())
    await settled(reports, expecting=1)

    denied_at = datetime.fromisoformat(reports.only()["denied_at"])
    assert denied_at.tzinfo is not None
    assert denied_at.utcoffset().total_seconds() == 0


@pytest.mark.asyncio
async def test_the_gateways_verdict_is_reported_under_the_key_rail_center_reads():
    """Two things at once, and they are the same defect from two sides.

    The key is the wire format Rail Center matches exactly with no fallback, so
    a rename blanks the operator-facing column. And what goes under it is **this
    gateway's** reading of the ticket — never the caller's own claim about it,
    which arrives under a key that says `claimed` and which `denial.py` calls
    the one thing that must never happen."""
    enforcement, _, reports = layer(bundle(DENIES_EVERYTHING))

    await drive(
        enforcement, call(), headers=[(b"x-rail-status", b"issuer-unreachable")]
    )
    await settled(reports, expecting=1)
    metadata = reports.only()["metadata"]

    assert metadata[WIRE_STATUS_KEY] == "absent"
    assert metadata[WIRE_CLAIMED_KEY] == "issuer-unreachable"


@pytest.mark.asyncio
async def test_a_repeated_status_header_is_not_a_claim():
    """Dropped the way a repeated ticket is refused: two claims are not a claim,
    and taking the first would let a caller choose which one is recorded."""
    enforcement, _, reports = layer(bundle(DENIES_EVERYTHING))

    await drive(
        enforcement,
        call(),
        headers=[(b"x-rail-status", b"not-found"), (b"x-rail-status", b"expired")],
    )
    await settled(reports, expecting=1)

    assert WIRE_CLAIMED_KEY not in reports.only()["metadata"]


@pytest.mark.asyncio
async def test_a_claimed_status_is_bounded_and_stripped_of_control_characters():
    """The last place either bound can be applied: Rail Center stores `metadata`
    free-form with no request-size limit in front of it, and the caller chooses
    when a denial happens by sending no ticket."""
    forged = b"not-found\x9b[31mFAKE"
    enforcement, _, reports = layer(bundle(DENIES_EVERYTHING))
    await drive(enforcement, call(), headers=[(b"x-rail-status", forged)])
    await settled(reports, expecting=1)
    assert reports.only()["metadata"][WIRE_CLAIMED_KEY] == "<unprintable>"

    enforcement, _, reports = layer(bundle(DENIES_EVERYTHING))
    await drive(enforcement, call(), headers=[(b"x-rail-status", b"n" * 60_000)])
    await settled(reports, expecting=1)
    recorded = reports.only()["metadata"][WIRE_CLAIMED_KEY]
    assert len(recorded) < 300
    assert recorded.endswith("…<truncated>")


@pytest.mark.asyncio
async def test_the_resolution_travels_beside_the_key_rather_than_inside_it():
    """A call that resolved to nothing must stay distinguishable from an
    endpoint that simply has no rule, so the status is reported even though the
    key it describes is null."""
    enforcement, _, reports = layer(bundle(DENIES_EVERYTHING))

    await drive(enforcement, KEYLESS)
    await settled(reports, expecting=1)
    body = reports.only()

    assert body["endpoint_key"] is None
    assert body["metadata"]["endpoint_resolution"] == "keyless"


@pytest.mark.asyncio
async def test_a_claim_rail_center_would_refuse_is_dropped_rather_than_sent():
    """`agent_id` is a `uuid.UUID` in Rail Center's schema and `posture_score` a
    number, and on `POST /v1/denials` a 422 means the denial is not recorded at
    all. The ticket is unsigned, so both are attacker-chosen: sending them back
    verbatim lets any caller suppress its own denial row by choosing a name.
    Dropping a malformed claim costs a column; sending it costs the row."""
    enforcement, _, reports = layer(bundle(DENIES_ANY_TICKET))

    header = ticket(agent_id="agent-42", posture_score="very-low").encode()
    await drive(enforcement, call(), headers=[(b"x-rail", header)])
    await settled(reports, expecting=1)
    body = reports.only()

    assert "agent_id" not in body
    assert "posture_score" not in body


@pytest.mark.asyncio
@pytest.mark.parametrize("claimed", [True, False], ids=["true", "false"])
async def test_a_boolean_posture_score_is_dropped_rather_than_recorded_as_a_number(
    claimed,
):
    """The worse of the two failures this guard handles, and the reason the bool
    check comes before the numeric one. `isinstance(True, int)` is true, so
    without it a `posture_score` of `true` is not refused by Rail Center — it is
    **accepted**, and lands on the record as `1.0`. The ticket is unsigned, so
    the claim is the caller's to choose, and a plausible-looking score is one
    nobody goes back and questions; the malformed and infinite claims beside it
    at least cost a visibly absent column."""
    enforcement, _, reports = layer(bundle(DENIES_ANY_TICKET))

    header = ticket(posture_score=claimed).encode()
    await drive(enforcement, call(), headers=[(b"x-rail", header)])
    await settled(reports, expecting=1)
    body = reports.only()

    assert "posture_score" not in body
    # The rest of the report is unaffected: one bad claim costs its own column.
    assert body["agent_id"] == "5c8f1e42-0000-4000-8000-00000000a9e7"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "literal",
    ["1e400", "-1e400", "1" + "0" * 400],
    ids=["overflows", "overflows-negative", "long-integer"],
)
async def test_a_posture_score_that_overflows_is_dropped_rather_than_losing_the_row(
    literal,
):
    """The ticket parser reads numbers with `parse_int=float` by design, so each
    of these arrives as an infinity. httpx serialises the report with
    `allow_nan=False` and `report` catches everything, so passing one through
    loses the whole denial silently — the suppression a caller gets for free on
    an unsigned claim. Written as the raw literal it is on the wire: `json.dumps`
    would emit `Infinity`, which is not JSON and which `gateway.ticket` refuses
    at its own door."""
    enforcement, _, reports = layer(bundle(DENIES_ANY_TICKET))

    raw = (
        b'{"agent_id": "5c8f1e42-0000-4000-8000-00000000a9e7", '
        b'"exp": 4102444800, "posture_score": ' + literal.encode() + b"}"
    )
    header = base64.urlsafe_b64encode(raw).decode().rstrip("=").encode()
    await drive(enforcement, call(), headers=[(b"x-rail", header)])
    await settled(reports, expecting=1)

    assert "posture_score" not in reports.only()


#: The undashed spelling of the `agent_id` every test here sends.
UNDASHED_AGENT = "5c8f1e4200004000800000000000a9e7"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "agent",
    [
        "5c8f1e42-0000-4000-8000-00000000a9e7",
        "5C8F1E42-0000-4000-8000-00000000A9E7",
        UNDASHED_AGENT,
        "{5c8f1e42-0000-4000-8000-00000000a9e7}",
        "urn:uuid:5c8f1e42-0000-4000-8000-00000000a9e7",
    ],
    ids=["canonical", "uppercase", "undashed", "braced", "urn"],
)
async def test_a_well_formed_claim_is_passed_through(agent):
    """The other half of the guard: it drops what the schema refuses and keeps
    what it declares, rather than dropping the column altogether. All four
    spellings `DenialEventRequest` reads travel, so narrowing the guard cannot
    quietly cost a column that works today."""
    enforcement, _, reports = layer(bundle(DENIES_ANY_TICKET))

    header = ticket(agent_id=agent, posture_score=10).encode()
    await drive(enforcement, call(), headers=[(b"x-rail", header)])
    await settled(reports, expecting=1)
    body = reports.only()

    assert body["agent_id"] == agent
    assert body["posture_score"] == 10


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "agent",
    [
        "5c8f1e42000040008000-00000000a9e7",
        "-" + UNDASHED_AGENT,
        "-".join(UNDASHED_AGENT),
        "{" + UNDASHED_AGENT + "}",
        "urn:uuid:" + UNDASHED_AGENT,
    ],
    ids=[
        "regrouped",
        "leading-hyphen",
        "hyphen-per-digit",
        "braced-undashed",
        "urn-undashed",
    ],
)
async def test_a_spelling_only_uuid_uuid_reads_is_dropped(agent):
    """`uuid.UUID` strips every hyphen before counting digits and takes braces
    and `urn:uuid:` off the undashed form, so it reads all five of these as the
    same id. Pydantic — which is what actually parses the field — refuses every
    one with `invalid group count` or `invalid length`, and a 422 here means the
    denial is not recorded at all. The ticket is unsigned, so the spelling is
    the caller's to choose."""
    enforcement, _, reports = layer(bundle(DENIES_ANY_TICKET))

    header = ticket(agent_id=agent, posture_score=10).encode()
    await drive(enforcement, call(), headers=[(b"x-rail", header)])
    await settled(reports, expecting=1)
    body = reports.only()

    assert "agent_id" not in body
    assert body["posture_score"] == 10


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "agent",
    [
        "5c8f1e42-0000-4000-8000-00000000a9e7X",
        "5c8f1e42-0000-4000-8000-00000000a9e7-junk",
        "5c8f1e42-0000-4000-8000-00000000a9e7 ",
        "5c8f1e42-0000-4000-8000-00000000a9e7\n",
        UNDASHED_AGENT + "deadbeef",
        "urn:uuid:5c8f1e42-0000-4000-8000-00000000a9e7}",
        "{5c8f1e42-0000-4000-8000-00000000a9e7}x",
    ],
    ids=[
        "trailing-character",
        "trailing-word",
        "trailing-space",
        "trailing-newline",
        "forty-hex",
        "urn-then-brace",
        "braced-then-character",
    ],
)
async def test_a_well_formed_spelling_followed_by_anything_is_dropped(agent):
    """The anchoring, which is the whole of what stands between the guard and
    the defect it replaced. `_READ_BY_RAIL_CENTER` is written unanchored and
    relied on being matched with `fullmatch`; matched with `match` it admits
    every one of these, and the real `DenialEventRequest` 422s every one with
    `invalid character` or `invalid length` — so an unanchored guard hands a
    caller back the suppression the guard exists to close, on a claim the
    unsigned ticket lets them choose.

    Every spelling in the sibling above fails at position 0, so none of them can
    catch a prefix match. These all begin with a spelling that is genuinely
    accepted and put the fault after it."""
    enforcement, _, reports = layer(bundle(DENIES_ANY_TICKET))

    header = ticket(agent_id=agent, posture_score=10).encode()
    await drive(enforcement, call(), headers=[(b"x-rail", header)])
    await settled(reports, expecting=1)
    body = reports.only()

    assert "agent_id" not in body
    assert body["posture_score"] == 10


# --------------------------------------------------------------------------
# F-011 — what happens when the report does not land
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_report_rail_center_refuses_is_named_in_the_log(caplog):
    """The only signal that this gateway and Rail Center disagree about the
    shape of a denial. A 422 swallowed as success is a missing row and a silent
    schema drift, which is the failure this whole path exists to make visible."""
    reports = _Reports(status=422)
    enforcement, _, _ = layer(bundle(DENIES_EVERYTHING), reports=reports)

    with caplog.at_level(logging.WARNING, logger="gateway.denial"):
        await drive(enforcement, call())
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
        _Holder(bundle(fallback="block")),
        rail_center_url=RAIL_CENTER_URL,
        auth={"Authorization": "Bearer t"},
        transport=httpx.MockTransport(unreachable),
    )

    with caplog.at_level(logging.WARNING, logger="gateway.denial"):
        assert (await drive(enforcement, call())).status == 403
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
    enforcement, _, _ = layer(bundle(DENIES_EVERYTHING), reports=reports)

    with caplog.at_level(logging.WARNING, logger="gateway.denial"):
        await drive(enforcement, call())
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
    enforcement, _, reports = layer(bundle(DENIES_EVERYTHING))

    await drive(enforcement, call())
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
    enforcement, _, _ = layer(bundle(DENIES_EVERYTHING), reports=reports)

    await drive(enforcement, call())
    for _ in range(50):
        await asyncio.sleep(0)

    assert len(enforcement._reports) == 1
    assert not next(iter(enforcement._reports)).done()

    hold.set()
    await settled(reports, expecting=1)

    assert enforcement._reports == set()


@pytest.mark.asyncio
async def test_a_walk_that_raises_forwards_rather_than_refusing(caplog, monkeypatch):
    """A defect in the walk must not take the forward path down. The trade is
    stated in `_judge` and is the same one `_UpstreamErrorBoundary` makes — a
    gateway that forwards nothing is worse than one that enforces nothing — and
    turning this into a 503 reverses it, so an unforeseen bug becomes a total
    outage rather than a logged traceback."""

    def explode(*_args, **_kwargs):
        raise RuntimeError("a defect in the walk")

    monkeypatch.setattr("gateway.server.decide", explode)
    enforcement, downstream, reports = layer(bundle(DENIES_EVERYTHING))

    with caplog.at_level(logging.ERROR, logger="gateway"):
        answer = await drive(enforcement, call())
    await settled(reports, expecting=0)

    assert answer.status == 200
    assert downstream.calls == 1
    assert reports.bodies == []
    assert "a defect in the walk" in caplog.text


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

#: An alert on any ticket. It is in the chain so that a case can bind an
#: endpoint to something without that something denying — what is being asserted
#: is that the walk happened, not what it concluded.
NOTES_ANY_TICKET = policy(
    SKILL_ID, {"field": "agent_id", "operator": "present"}, action="alert"
)

#: `delivery#/mcp#tools/call#track_package`, gated to the one policy above. A
#: binding *entry* is what the fallback looks for; which policies it names is the
#: chain's business. A binding as the bundle carries it — the **full** key, with
#: the data source slug Rail Center composed it from. The gateway strips that
#: first segment and matches the rest against what it composed from the request,
#: so a fixture carrying the comparable form would pass while testing nothing
#: about the strip.
FULL_KEY = f"{SLUG}#{KEY}"
BOUND = {"endpoint_key": FULL_KEY, "mode": "gated", "policy_ids": [SKILL_ID]}


@pytest.mark.asyncio
async def test_an_unbound_endpoint_is_refused_under_a_block_fallback():
    """The chain is empty, so nothing in it can deny — and the call is still
    refused. That is what makes the 403 the fallback's rather than a policy's.
    """
    enforcement, downstream, _ = layer(bundle(fallback="block"))

    answer = await drive(enforcement, call(), headers=[(b"x-rail", ticket().encode())])

    assert answer.status == 403
    assert downstream.calls == 0


@pytest.mark.asyncio
async def test_an_endpoint_with_a_binding_entry_is_judged_rather_than_refused():
    """`block` refuses the *unbound*, and a bound endpoint is not that however
    little its binding narrows to. A fallback that read the bundle's bindings as
    a whitelist of keys to be walked would pass the case above and fail this
    one."""
    enforcement, downstream, _ = layer(
        bundle(NOTES_ANY_TICKET, bindings=[BOUND], fallback="block")
    )

    answer = await drive(enforcement, call(), headers=[(b"x-rail", ticket().encode())])

    assert answer.status == 200
    assert downstream.calls == 1


@pytest.mark.asyncio
async def test_a_pass_fallback_hands_an_unbound_endpoint_to_the_whole_chain():
    """Both halves, because `pass` means *not refused for being unbound* and not
    *unjudged*: the same unbound call is forwarded under a chain that allows and
    refused under one that denies.
    """
    enforcement, downstream, _ = layer(bundle(fallback="pass"))
    assert (
        await drive(enforcement, call(), headers=[(b"x-rail", ticket().encode())])
    ).status == 200
    assert downstream.calls == 1

    enforcement, downstream, _ = layer(bundle(DENIES_EVERYTHING, fallback="pass"))
    assert (await drive(enforcement, call())).status == 403
    assert downstream.calls == 0


@pytest.mark.asyncio
async def test_a_block_fallback_is_consulted_at_enforce_and_nowhere_else():
    """`observe` and `none` hold the same `block` and act on neither.

    A gateway that refused here would have made `observe` block traffic, which
    is the one thing an operator uses `observe` to be sure it will not do.
    """
    for mode in ("observe", "none"):
        enforcement, downstream, _ = layer(bundle(enforcement=mode, fallback="block"))
        answer = await drive(
            enforcement, call(), headers=[(b"x-rail", ticket().encode())]
        )
        assert answer.status == 200, mode
        assert downstream.calls == 1, mode


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
    enforcement, downstream, _ = layer(bundle(fallback="block"))

    with caplog.at_level(logging.INFO, logger="gateway"):
        answer = await drive(
            enforcement, call(), headers=[(b"x-rail", ticket().encode())]
        )

    assert answer.status == 403
    assert downstream.calls == 0
    written = "\n".join(caplog.messages)
    assert "denied" in written and "fallback=block" in written
    assert "would deny" not in written


@pytest.mark.asyncio
async def test_the_caller_cannot_tell_a_fallback_refusal_from_a_policy_denial():
    """Standard deny mechanics, and the reason is not tidiness.

    A status or reason of its own here answers a question no caller is entitled
    to ask: holding a tool name, anyone could learn whether this gateway has a
    binding for it, one call at a time, and assemble a map of which of the
    tenant's endpoints are covered. It is the leak the policy id is already
    withheld to prevent, and a more useful one.
    """
    unbound, _, _ = layer(bundle(fallback="block"))
    by_policy, _, _ = layer(bundle(DENIES_EVERYTHING, fallback="pass"))

    one = await drive(unbound, call())
    other = await drive(by_policy, call())

    assert one.status == other.status == 403
    assert one.body == other.body


@pytest.mark.asyncio
async def test_a_fallback_refusal_is_reported_as_a_denial_carrying_no_policy() -> None:
    """The one verdict this gateway reaches without a rule, and it is still a
    denial.

    `block` refuses a call no binding matched without the chain being consulted
    at all, so there is no policy to name — and the report omits `policy_id`
    rather than inventing one or sending null. Leaving it unreported would make
    the endpoints nobody bound the only ones whose refusals never reach an
    operator, which is the opposite of what an unbound endpoint deserves.
    """
    enforcement, _, reports = layer(bundle(fallback="block"))

    assert (await drive(enforcement, call())).status == 403
    await settled(reports, expecting=1)

    (body,) = reports.bodies
    assert "policy_id" not in body
    assert body["endpoint_key"] == KEY
    assert body["metadata"]["endpoint_resolution"] == "resolved"


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
    enforcement, downstream, _ = layer(bundle(fallback="block"), reports=reports)

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
        bundle(
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

    assert (await drive(enforcement, call())).status == 403

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
    enforcement, downstream, _ = layer(bundle(DENIES_EVERYTHING), reports=reports)

    for n in range(MAX_REPORTS_IN_FLIGHT + 10):
        assert (await drive(enforcement, call())).status == 403, n
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
    enforcement, downstream, _ = layer(bundle(fallback="block"), reports=reports)

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
    enforcement, _, _ = layer(bundle(fallback="block"))

    with caplog.at_level(logging.WARNING, logger="gateway"):
        await drive(enforcement, call())

    written = "\n".join(caplog.messages)
    assert KEY in written
    assert "fallback=block" in written
    # The refusal *is* reported — what the caller is not told is which
    # endpoint has no binding, and the log is where that lives.
    assert "no policy judged it" in written


@pytest.mark.asyncio
async def test_a_message_naming_no_tool_by_design_is_not_an_unbound_endpoint():
    """`resources/read` names no endpoint, so a fallback about endpoints has
    nothing to refuse and the call is judged. Refusing it would let a `block`
    fallback close the session messages that carry no tool name."""
    enforcement, downstream, _ = layer(bundle(fallback="block"))

    answer = await drive(enforcement, KEYLESS, headers=[(b"x-rail", ticket().encode())])

    assert answer.status == 200
    assert downstream.calls == 1


@pytest.mark.asyncio
async def test_a_tools_call_that_resolved_to_nothing_is_refused_under_block():
    """It named a tool this gateway declined to compose a key for, so no binding
    can match it — and under a posture that refuses what nobody bound, the input
    this gateway understands least is not the one that gets the benefit of the
    doubt."""
    enforcement, downstream, _ = layer(bundle(fallback="block"))

    answer = await drive(
        enforcement, call("track_package\n"), headers=[(b"x-rail", ticket().encode())]
    )

    assert answer.status == 403
    assert downstream.calls == 0


@pytest.mark.asyncio
async def test_a_session_message_is_not_refused_by_the_fallback():
    """Discovery is passed before the bundle is even read, so the strictest
    posture there is cannot stop a session from opening."""
    enforcement, downstream, _ = layer(bundle(fallback="block"))

    for body in DISCOVERY:
        assert (await drive(enforcement, body)).status == 200

    assert downstream.calls == len(DISCOVERY)


# --------------------------------------------------------------------------
# F-003 — which absent key earns the keyless narrowing
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_message_that_names_no_tool_by_design_keeps_the_narrowing():
    """`resources/read` names no endpoint, so a rule keyed on one asks a
    question with no subject and leaves the chain, while the rest still holds.
    """
    enforcement, downstream, _ = layer(bundle(DENIES_UNMATCHED_SKILL))

    answer = await drive(enforcement, KEYLESS, headers=[(b"x-rail", ticket().encode())])

    assert answer.status == 200
    assert downstream.calls == 1


@pytest.mark.asyncio
async def test_a_tools_call_this_gateway_could_not_resolve_faces_the_whole_chain():
    """It named a tool — the gateway just declined to compose a key for it — so
    there is a subject and the endpoint-derived rules stay. Reading the absent
    key alone instead would let a caller shed every one of them by appending a
    newline to a tool name, which is the input this gateway understands least."""
    unresolvable = (
        call("track_package\n"),
        json.dumps({"method": "tools/call", "params": {}}).encode(),
        b"not json at all",
    )
    for body in unresolvable:
        enforcement, downstream, _ = layer(bundle(DENIES_UNMATCHED_SKILL))
        answer = await drive(
            enforcement, body, headers=[(b"x-rail", ticket().encode())]
        )
        assert answer.status == 403, body
        assert downstream.calls == 0


# --------------------------------------------------------------------------
# A session message is not a call
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_session_message_passes_without_a_ticket_and_reports_nothing():
    """`initialize`, `notifications/initialized` and `tools/list` open the
    session and describe its surface. A bundle that denies every ticket has no
    say over them: the call that follows is where the ticket is judged, and a
    denial reported here would attribute a verdict no walk reached."""
    for body in DISCOVERY:
        enforcement, downstream, reports = layer(bundle(DENIES_EVERYTHING))
        answer = await drive(enforcement, body)
        assert answer.status == 200, body
        assert downstream.calls == 1, body
        await settled(reports, expecting=0)
        assert reports.bodies == [], body


@pytest.mark.asyncio
async def test_a_session_message_passes_when_no_bundle_is_held():
    """A gateway holding no ruleset refuses every call with 503, and still lets
    a session open: the 503 is answered on the call, where it is meaningful."""
    for body in DISCOVERY:
        enforcement, downstream, _ = layer(None)
        answer = await drive(enforcement, body)
        assert answer.status == 200, body
        assert downstream.calls == 1, body


@pytest.mark.asyncio
async def test_a_rule_bound_to_one_endpoint_does_not_close_the_session():
    """The reason the pass exists. A rule denying every ticket, bound to one
    endpoint, must leave `initialize` alone and still deny the call it names."""
    narrowed = bundle(
        DENIES_ANY_TICKET,
        bindings=[{"endpoint_key": KEY, "mode": "gated", "policy_ids": [DENY_ID]}],
    )
    enforcement, downstream, _ = layer(narrowed)
    opened = await drive(
        enforcement, DISCOVERY[0], headers=[(b"x-rail", ticket().encode())]
    )
    assert opened.status == 200
    called = await drive(enforcement, call(), headers=[(b"x-rail", ticket().encode())])
    assert called.status == 403
    assert downstream.calls == 1


# --------------------------------------------------------------------------
# F-005 — reading the body without swallowing a disconnect
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_body_arriving_in_chunks_reaches_the_app_below_intact():
    enforcement, downstream, _ = layer(bundle(DENIES_EVERYTHING), blocking=False)
    whole = call()
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
    enforcement, downstream, _ = layer(bundle(DENIES_EVERYTHING), blocking=False)
    whole = call()

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
    held = bundle(DENIES_UNMATCHED_SKILL, bindings=EXEMPT)
    whole = call()
    carrying = [(b"x-rail", ticket(posture_score=90).encode())]

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
    enforcement, downstream, reports = layer(bundle(DENIES_UNMATCHED_SKILL))

    answer = await drive(
        enforcement,
        headers=[(b"x-rail", ticket().encode()), (b"content-length", b"900")],
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
    exact format `_judge` writes a real denial in, and a live ANSI escape aimed
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
            enforcement, _, reports = layer(bundle(DENIES_EVERYTHING))
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


@pytest.mark.asyncio
async def test_a_request_that_is_not_a_post_is_not_judged():
    """`/health`, `/ready` and the GET that opens the event stream name no
    endpoint, so there is nothing to judge and the body is never read."""
    enforcement, downstream, reports = layer(bundle(DENIES_EVERYTHING))

    answer = await drive(enforcement, b"", method="GET")
    await settled(reports, expecting=0)

    assert answer.status == 200
    assert downstream.calls == 1
    assert reports.bodies == []


# --------------------------------------------------------------------------
# F-019 — a body too deep to parse still gets an answer
# --------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("depth", [MAX_BODY_NESTING_DEPTH + 1, 1000, 10000])
async def test_a_body_too_deep_to_read_is_refused_rather_than_raising(depth):
    """`json.loads` raises `RecursionError` past a depth the runtime picks, and
    `_judge` resolves the body on its first line — above the `try` whose
    `except Exception` exists so a defect in the walk cannot take the forward
    path down. Left unguarded, a caller-chosen kilobyte of brackets raises
    straight out of the ASGI layer and the caller gets neither the refusal nor
    the forward.

    The body reads as `unrecognised`, which faces the whole chain, so the
    denying chain here refuses it and the denial is reported like any other."""
    enforcement, downstream, reports = layer(bundle(DENIES_EVERYTHING))

    answer = await drive(enforcement, deep_call(depth))
    await settled(reports, expecting=1)

    assert answer.status == 403
    assert downstream.calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("depth", [MAX_BODY_NESTING_DEPTH + 1, 1000, 10000])
async def test_a_body_too_deep_to_read_is_still_forwarded_under_observe(depth):
    """The half of the same fault that costs more. Under `observe` the module
    promises the call goes upstream exactly as it would have without any of
    this, and an exception out of the resolve means it is not forwarded at all
    — a gateway that forwards nothing is worse than one that enforces nothing.
    The body reaching the app below is the one that arrived on the wire."""
    enforcement, downstream, reports = layer(bundle(DENIES_EVERYTHING), blocking=False)
    body = deep_call(depth)

    answer = await drive(enforcement, body)
    await settled(reports, expecting=0)

    assert answer.status == 200
    assert downstream.calls == 1
    assert downstream.body == body


# --- what a denial names, and at which posture the fallback is asked ---------
#
# Two rules that only show up in a report, and one that only shows up in a log.
# Both were settled in RC-312's plan and neither is visible from the caller's
# side, which is what makes them worth pinning here rather than inferring from
# a 403.


@pytest.mark.asyncio
async def test_a_denial_on_a_matched_binding_names_the_key_rail_center_published() -> (
    None
):
    """The full key, taken off the binding rather than recomposed.

    This gateway composes `<path>#<method>#<call>` and holds no slug, so the key
    it built is not the key Rail Center stores. Where a binding matched, the
    whole key is in hand — it arrived in the bundle — and reporting that one
    lets the receiver resolve the data source without re-deriving it from the
    gateway's routing. Reporting the composed form instead would throw away the
    only part the gateway could not have known.
    """
    bound_to_the_denying_rule = {
        "endpoint_key": FULL_KEY,
        "mode": "gated",
        "policy_ids": [DENY_ID],
    }
    enforcement, _, reports = layer(
        bundle(DENIES_EVERYTHING, bindings=[bound_to_the_denying_rule], fallback="pass")
    )

    assert (await drive(enforcement, call())).status == 403
    await settled(reports, expecting=1)

    (body,) = reports.bodies
    assert body["endpoint_key"] == FULL_KEY
    assert body["endpoint_key"] != KEY


@pytest.mark.asyncio
async def test_a_denial_on_no_binding_names_the_only_key_there_is() -> None:
    """The other half, and the reason the first is not simply "always the full
    key": where nothing matched there is no published key to name, so the
    composed form is all this gateway holds."""
    enforcement, _, reports = layer(bundle(DENIES_EVERYTHING, fallback="pass"))

    assert (await drive(enforcement, call())).status == 403
    await settled(reports, expecting=1)

    (body,) = reports.bodies
    assert body["endpoint_key"] == KEY


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
        bundle(DENIES_EVERYTHING, fallback="block"), blocking=False
    )

    # Captured at WARNING, which `RAIL_GATEWAY_LOG_LEVEL` accepts: the preview
    # an operator reads before turning `block` on has to survive the level they
    # are most likely to run, and the policy preview beside it already does.
    with caplog.at_level(logging.WARNING, logger="gateway"):
        answer = await drive(enforcement, call())

    assert answer.status == 200, "observe acts on nothing, the fallback included"
    written = "\n".join(caplog.messages)
    assert "would deny" in written and "fallback=block" in written
    assert "would deny" in written and DENY_ID in written, (
        "the chain was walked as well, so its verdict is in the log too"
    )
    await settled(reports, expecting=0)
    assert reports.bodies == [], "a report is an action, and observe takes none"
