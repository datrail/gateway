"""What the gateway does with a verdict, which in this build is write it down.

The walk itself is pinned by `tests/vectors/decide.json`, which
`tests/test_vectors.py` runs; the one walk rule no vector reaches — a call
naming no endpoint — by `tests/test_decide.py`; and how a message resolves to a
key at all by `tests/test_endpoint.py`. This file is about the wiring around
those: that a request reaches the walk with the right ticket and the right
endpoint key, that the answer reaches the log, and that **nothing the walk
concludes changes what the caller gets**.

That last one is the whole of `observe`, and it is asserted rather than assumed
on every case below: a denied call and an allowed call must come back
identically, because the only difference between them today is a line in a log.
Wiring a refusal in later is then a change that fails these tests rather than
one that passes quietly.
"""

from __future__ import annotations

import base64
import json
import logging

import httpx
import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

from gateway.server import build_app
from tests.conftest import (
    RAIL_CENTER,
    SLUG,
    _free_port,
    holder_serving,
    serve,
    unreachable,
)

#: A chain with one rule of each action, so a single bundle exercises deny,
#: alert and allow depending on the ticket presented.
DENY_ID = "5c8f1e42-0000-4000-8000-0000000000d1"
ALERT_ID = "5c8f1e42-0000-4000-8000-0000000000a1"

BUNDLE = {
    "version": "v-evaluate",
    "policies": [
        {
            "id": DENY_ID,
            "name": "deny an unscored or low-scoring agent",
            "priority": 1,
            "condition": {"field": "posture_score", "operator": "lt", "value": 40},
            "action": "block",
            "enabled": True,
        },
        {
            "id": ALERT_ID,
            "name": "note every call to this data source",
            "priority": 2,
            "condition": {
                "field": "endpoint_key",
                "operator": "matches",
                "value": f"{SLUG}.*",
            },
            "action": "alert",
            "enabled": True,
        },
    ],
    "bindings": [],
    "rejected": [],
    # The posture these tests run at, and it arrives here rather than in
    # `build_app` because that is where it arrives in production (RC-312).
    # `observe` evaluates every call and refuses none, which is what makes a
    # would-deny assertable without a 403 standing in the way of the forward
    # path most of these cases are checking.
    "enforcement": {"mode": "observe", "fallback": "block"},
}


def ticket(**claims) -> str:
    """An `x-rail` header carrying `claims`, unpadded as the mint emits it."""
    claims.setdefault("agent_id", "agent-1")
    claims.setdefault("exp", 4102444800)  # 2100-01-01, comfortably unexpired
    raw = json.dumps(claims).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def serving(bundle) -> object:
    return holder_serving(lambda: httpx.Response(200, json=bundle))


async def call(gateway_url: str, headers: dict[str, str] | None = None) -> str:
    """Make the one tool call this suite uses, and return its text."""
    async with Client(
        StreamableHttpTransport(url=f"{gateway_url}/mcp", headers=headers or {})
    ) as client:
        result = await client.call_tool("track_package", {"tracking_number": "77123"})
    return result.content[0].text


@pytest.fixture
def evaluating(upstream):
    """A gateway holding `BUNDLE` and evaluating every call against it."""
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def start(bundle=BUNDLE):
        port = _free_port()
        app = build_app(upstream, serving(bundle), slug=SLUG, rail_center=RAIL_CENTER)
        async with serve(app, port):
            yield f"http://127.0.0.1:{port}"

    return start


# --- the verdict reaches the log, and nothing else ------------------------


@pytest.mark.asyncio
async def test_a_call_that_would_be_denied_is_forwarded_anyway(evaluating, caplog):
    """The assertion this branch exists to make. The walk denies, the log says
    so and names the policy that actually matched, and the caller gets the
    upstream's answer exactly as an allowed caller would."""
    with caplog.at_level(logging.INFO, logger="gateway"):
        async with evaluating() as url:
            answer = await call(url, {"x-rail": ticket(posture_score=10)})

    assert answer == "delivered:77123"
    written = "\n".join(caplog.messages)
    assert "would deny" in written
    assert DENY_ID in written, "the denial names the policy that matched"


@pytest.mark.asyncio
async def test_an_allowed_call_says_so(evaluating, caplog):
    with caplog.at_level(logging.INFO, logger="gateway"):
        async with evaluating() as url:
            answer = await call(url, {"x-rail": ticket(posture_score=95)})

    assert answer == "delivered:77123"
    written = "\n".join(caplog.messages)
    assert "allow" in written
    assert "would deny" not in written


@pytest.mark.asyncio
async def test_an_alert_is_written_and_denies_nothing(evaluating, caplog):
    """An `alert` never stops the walk and never denies, so a call matching only
    the alert rule is allowed and still reported."""
    with caplog.at_level(logging.INFO, logger="gateway"):
        async with evaluating() as url:
            await call(url, {"x-rail": ticket(posture_score=95)})

    written = "\n".join(caplog.messages)
    assert ALERT_ID in written
    assert "alerts on" in written


@pytest.mark.asyncio
async def test_the_endpoint_key_is_the_slug_and_the_tool_name(evaluating, caplog):
    """`<slug>.<tool_name>`, composed here because nothing else can: MCP puts
    the call's identity in the message rather than the URL."""
    with caplog.at_level(logging.INFO, logger="gateway"):
        async with evaluating() as url:
            await call(url, {"x-rail": ticket(posture_score=95)})

    assert f"{SLUG}.track_package" in "\n".join(caplog.messages)


# --- the ticket reaches the walk as the contract requires ------------------


@pytest.mark.asyncio
async def test_a_repeated_x_rail_header_is_undecodable(evaluating, caplog):
    """The contract refuses a repeated header outright, and says why it cannot
    be deferred: once a platform collapses two values into one the evidence is
    gone. `get_http_headers()` returns a dict and `Headers.get` takes the first
    value — either would admit a ticket an attacker chose by sending the header
    twice. This passes only while the reader uses `getlist`.

    **Both values are tickets that would be `valid` on their own**, and a raw
    POST is what carries them. Two things follow, and the test is worth nothing
    without either. `StreamableHttpTransport` hands its `headers` to httpx as
    *client*-level headers, where the second pair replaces the first — the
    server then receives one value, and a reader that flattens `getlist` passes
    anyway. And a second value that is garbage on its own reads `undecodable`
    whatever the reader does, so it would pass against a reader taking the
    first, the last, or the joined list. Together these make the only way to
    read `undecodable` here be refusing the repeat itself.
    """
    first = ticket(posture_score=95)
    second = ticket(posture_score=95, agent_id="agent-2")
    with caplog.at_level(logging.INFO, logger="gateway"):
        async with evaluating() as url:
            async with httpx.AsyncClient() as raw:
                response = await raw.post(
                    f"{url}/mcp",
                    headers=[
                        ("content-type", "application/json"),
                        ("accept", "application/json, text/event-stream"),
                        ("x-rail", first),
                        ("x-rail", second),
                    ],
                    content=json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "resources/read",
                            "params": {
                                "protocolVersion": "2025-06-18",
                                "capabilities": {},
                                "clientInfo": {"name": "repeat-probe", "version": "1"},
                            },
                        }
                    ),
                )

    # Forwarded rather than refused: the MCP server answers a session-less
    # `resources/read` with 400, and that answer arriving at all is what makes
    # the line below evidence about the reader rather than about the transport —
    # a refusal by the layer above would have been a 403 or 503 and no walk.
    assert response.status_code not in (403, 503), response.text
    written = "\n".join(caplog.messages)
    assert "(ticket undecodable)" in written
    # Neither value alone: either one taken singly is a usable ticket, and that
    # is the admission this pins.
    assert "(ticket valid)" not in written


@pytest.mark.asyncio
async def test_no_ticket_reads_as_absent(evaluating, caplog):
    with caplog.at_level(logging.INFO, logger="gateway"):
        async with evaluating() as url:
            await call(url)

    assert "absent" in "\n".join(caplog.messages)


# --- the three ways the walk cannot answer --------------------------------


@pytest.mark.asyncio
async def test_a_gateway_holding_no_bundle_forwards_and_says_it_judged_nothing(
    gateway_url, caplog
):
    """`gateway_url` never reaches its control plane. The contract's answer is
    to refuse; refusing is what this build does not do, so the honest report is
    that the request went unjudged rather than a verdict invented from an absent
    ruleset."""
    with caplog.at_level(logging.INFO, logger="gateway"):
        answer = await call(gateway_url)

    assert answer == "delivered:77123"
    assert "unjudged" in "\n".join(caplog.messages)


@pytest.mark.asyncio
async def test_a_condition_outside_the_grammar_forwards_and_reports_the_drift(
    evaluating, caplog
):
    """Rail Center can learn a field this gateway has not. Under enforcement
    that is a 503 and no denial report; here it is an error line naming the
    drift, which is the fault and the only thing that fixes it."""
    unreadable = {
        **BUNDLE,
        "policies": [
            {
                **BUNDLE["policies"][0],
                "condition": {"field": "moon_phase", "operator": "eq", "value": "full"},
            }
        ],
    }
    with caplog.at_level(logging.INFO, logger="gateway"):
        async with evaluating(bundle=unreadable) as url:
            answer = await call(url, {"x-rail": ticket(posture_score=10)})

    assert answer == "delivered:77123"
    written = "\n".join(caplog.messages)
    assert "drifted" in written
    assert "moon_phase" in written


# --- and the mode that evaluates nothing ----------------------------------


@pytest.mark.asyncio
async def test_none_evaluates_nothing_and_is_ready_without_a_bundle(upstream, caplog):
    """A pass-through. No holder is built, so nothing polls Rail Center and
    `/ready` cannot be waiting on a bundle — the deployment that turns
    enforcement off must not be the one that never serves."""
    port = _free_port()

    with caplog.at_level(logging.INFO, logger="gateway"):
        # Built inside the capture: the mode's startup line is written by
        # `build_gateway`, so building it first would emit the one line this
        # case is about before anything was listening.
        app = build_app(upstream, enrolled="none", slug=SLUG, rail_center=RAIL_CENTER)
        async with serve(app, port):
            url = f"http://127.0.0.1:{port}"
            async with httpx.AsyncClient() as client:
                assert (await client.get(f"{url}/ready")).status_code == 200
            answer = await call(url, {"x-rail": ticket(posture_score=10)})

    assert answer == "delivered:77123"
    written = "\n".join(caplog.messages)
    assert "no control plane" in written
    assert "fetches no policy bundle" in written
    # Nothing was judged, so nothing may be reported as judged.
    assert "would deny" not in written
    assert "allow " not in written


# --- RC-312: the posture arrives in the bundle, and moves without a restart ---
#
# PTH.G1's own Verify, and the reason the holder inversion exists. Before this,
# `RAIL_TICKET_MODE` was read once at start-up and a gateway told `none` built no
# holder at all — so the operator who disabled enforcement during an incident
# needed a redeploy to undo it, and the kill switch turned one way only.


def bundle_at(enforcement: str, fallback: str = "block"):
    """`BUNDLE`, at the posture a case is about.

    **The version moves with the posture, because in production it does.** Rail
    Center hashes `enforcement` into `version` (RC-312), and a fixture that held
    the version constant across a posture change would be modelling a control
    plane that does not exist — one whose kill switch cannot arrive. That is not
    a detail of this helper: it was written the other way first, and the Verify
    below failed against it exactly as the plan says it would.
    """
    return {
        **BUNDLE,
        "version": f"v-evaluate-{enforcement}-{fallback}",
        "enforcement": {"mode": enforcement, "fallback": fallback},
    }


@pytest.mark.asyncio
async def test_a_gateway_told_none_judges_nothing_and_keeps_its_bundle(
    evaluating, caplog
):
    """`none` is a posture held by a gateway in touch with its control plane.

    Two halves, and the second is the one that used to be false: nothing is
    judged, **and** the gateway is ready — it holds a bundle, so it is listening
    and can be told something else.
    """
    async with evaluating(bundle_at("none")) as url:
        with caplog.at_level(logging.INFO, logger="gateway"):
            answer = await call(url, {"x-rail": ticket(posture_score=10)})
        async with httpx.AsyncClient() as client:
            ready = await client.get(f"{url}/ready")

    assert answer == "delivered:77123"
    assert ready.status_code == 200, "a gateway at `none` holds a bundle and is ready"
    written = "\n".join(caplog.messages)
    assert "enforcement=none" in written
    assert "would deny" not in written and "allow " not in written


@pytest.mark.asyncio
async def test_moving_the_posture_takes_effect_on_the_next_poll(upstream, caplog):
    """The Verify, end to end: move a gateway in Rail Center and it acts on it.

    One process, one holder, two polls. The first says `none` and the call is
    forwarded unjudged; the second says `observe` and the same call is judged.
    Nothing restarts, and no environment variable moves — which is the whole
    claim RC-312 makes on this side.
    """
    posture = {"mode": "none"}
    holder = holder_serving(
        lambda: httpx.Response(200, json=bundle_at(posture["mode"]))
    )
    port = _free_port()
    app = build_app(upstream, holder, slug=SLUG, rail_center=RAIL_CENTER)

    async with serve(app, port):
        url = f"http://127.0.0.1:{port}"
        with caplog.at_level(logging.INFO, logger="gateway"):
            await call(url, {"x-rail": ticket(posture_score=10)})
            judged_at_none = "would deny" in "\n".join(caplog.messages)

            posture["mode"] = "observe"
            await holder.refresh()

            caplog.clear()
            await call(url, {"x-rail": ticket(posture_score=10)})
            judged_at_observe = "would deny" in "\n".join(caplog.messages)

    assert not judged_at_none, "a gateway told `none` judges nothing"
    assert judged_at_observe, "the move reached the gateway on its next poll"


@pytest.mark.asyncio
async def test_the_three_pass_traffic_states_are_not_each_other(upstream):
    """Three ways to forward every request, and an operator must be able to tell
    which one they have — `/ready` is where the difference is visible.

    No data path and `none` both forward and both report ready, and they are
    still distinguishable: one polls and one does not, which is what the log
    line says. Holding no bundle forwards too and reports **unready**, because
    it is the only one of the three that is waiting for something.
    """
    async with httpx.AsyncClient() as client:

        async def readiness(app):
            port = _free_port()
            async with serve(app, port):
                return (await client.get(f"http://127.0.0.1:{port}/ready")).status_code

        no_data_path = await readiness(
            build_app(upstream, enrolled="none", slug=SLUG, rail_center=RAIL_CENTER)
        )
        holding_none = await readiness(
            build_app(
                upstream,
                holder_serving(unreachable),
                slug=SLUG,
                rail_center=RAIL_CENTER,
            )
        )
        told_none = await readiness(
            build_app(
                upstream, serving(bundle_at("none")), slug=SLUG, rail_center=RAIL_CENTER
            )
        )

    assert no_data_path == 200, "nothing to wait for, and never will be"
    assert holding_none == 503, "waiting for a first bundle"
    assert told_none == 200, "holds a bundle, and was told to judge nothing"


@pytest.mark.asyncio
async def test_a_posture_change_under_an_unchanged_version_never_arrives(
    upstream, caplog
):
    """The other side of the same coin, and the reason Rail Center hashes this.

    A holder caches on `version`, so a control plane that moved a posture without
    moving the version would be telling a gateway nothing at all — every poller
    keeps what it holds and the change is silently dropped. This pins the
    dependency from the gateway's side: it is not a Rail Center implementation
    detail this component is indifferent to, it is the thing that makes the field
    work at all.
    """
    posture = {"mode": "none"}
    holder = holder_serving(
        # Deliberately one version for both postures — the bug, reproduced.
        lambda: httpx.Response(
            200,
            json={
                **BUNDLE,
                "enforcement": {"mode": posture["mode"], "fallback": "block"},
            },
        )
    )
    port = _free_port()
    app = build_app(upstream, holder, slug=SLUG, rail_center=RAIL_CENTER)

    async with serve(app, port):
        url = f"http://127.0.0.1:{port}"
        posture["mode"] = "observe"
        await holder.refresh()
        with caplog.at_level(logging.INFO, logger="gateway"):
            await call(url, {"x-rail": ticket(posture_score=10)})

    written = "\n".join(caplog.messages)
    assert "would deny" not in written, (
        "an unchanged version must not carry a posture change — if this starts "
        "passing, the holder has stopped caching on version and the hash "
        "argument in RC-312 needs revisiting"
    )
    assert "enforcement=none" in written
