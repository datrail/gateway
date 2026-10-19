"""Drives each standalone gateway and asserts what crossed the wire."""

import os
import time

import lib
from lib import (
    await_denial,
    await_last_denial,
    block,
    bundle_fetches,
    call_tool,
    denials,
    denials_naming_no_policy,
    expect,
    fail,
    finish,
    forwarded_tool_calls,
    get_status,
    handshake_status,
    ok,
    open_session,
    reset_journals,
    status,
    sweep_unmatched,
    wait_for,
)

GOOD = {"x-rail": os.environ["E2E_GOOD_TICKET"]}
LOW_SCORE = {"x-rail": os.environ["E2E_LOW_SCORE_TICKET"]}
LOW_SCORE_TICKET_ID = "5c8f1e42-0000-4000-8000-0000000000c2"

P1 = "11111111-0000-4000-8000-000000000001"
P2 = "11111111-0000-4000-8000-000000000002"
P3 = "11111111-0000-4000-8000-000000000003"


def mcp(host):
    return f"http://{host}:8080/mcp"


ENFORCE = mcp("gateway-enforce")
OBSERVE = mcp("gateway-observe")
FALLBACK = mcp("gateway-fallback")
PASSTHROUGH = mcp("gateway-passthrough")


def settle():
    """Long enough for a report or fetch to show up, if one were coming."""
    time.sleep(2)


# First, before any reset: bundles are fetched at startup, never per request, so
# this is the only place the pass-through's silence can be counted.
block("a bundle is fetched at startup, by the three gateways with a control plane")
wait_for(bundle_fetches, 3)
settle()
expect("exactly three gateways fetched a bundle", 3, bundle_fetches())

block(
    "enforce: a caller with no ticket opens a session and is stopped at its first call"
)
reset_journals()
expect("initialize is not refused", 200, handshake_status(ENFORCE))
expect("the call is refused 403", 403, status(ENFORCE, "track_package"))
expect("no call reached the upstream", 0, forwarded_tool_calls())
expect(
    "the ticket fallback refused it, naming no policy",
    1,
    wait_for(denials_naming_no_policy, 1),
)
expect(
    "and said which fallback",
    "ticket",
    (await_last_denial().get("metadata") or {}).get("fallback"),
)
# Catches a second report naming another rule, which the scoped count misses.
settle()
expect("exactly one denial was reported", 1, denials())

block(
    "enforce: a low-posture ticket opens a session and is stopped at its first call too"
)
reset_journals()
expect("initialize is not refused", 200, handshake_status(ENFORCE, LOW_SCORE))
expect("the call is refused 403", 403, status(ENFORCE, "track_package", LOW_SCORE))
expect("it named P1", 1, await_denial(1, P1))
# The ticket's id travels with the denial, and none of its claims do.
low_denial = await_last_denial()
expect("it carried the ticket's id", LOW_SCORE_TICKET_ID, low_denial.get("ticket_id"))
expect("and no score", "<none>", low_denial.get("posture_score", "<none>"))

block("enforce: a good ticket opens a session and its call is forwarded")
reset_journals()
sid = open_session(ENFORCE, GOOD)
if sid is None:
    fail("the handshake did not return a session id")
    sid = "none"
code, body = call_tool(
    ENFORCE,
    "track_package",
    {"tracking_number": "pkg-1"},
    {"Mcp-Session-Id": sid, **GOOD},
    request_id=2,
)
if code != 200:
    body = ""
if '"text":"delivered"' in body:
    ok("the tool call returns the upstream answer")
else:
    fail(f"the tool call returns the upstream answer — got {body}")
settle()
expect("no denial was reported", 0, denials())

block("enforce: an endpoint rule denies the call and not the handshake")
# The handshake is a session message: forwarded unjudged, whatever P2 says.
reset_journals()
sid = open_session(ENFORCE, GOOD) or "none"
expect("the handshake still succeeds", 1, 1 if sid != "none" else 0)
expect(
    "the forbidden call is refused 403",
    403,
    status(ENFORCE, "forbidden_tool", {"Mcp-Session-Id": sid, **GOOD}),
)
expect("it named P2, the endpoint rule", 1, await_denial(1, P2))
# A control character composes no key, so the call faces the whole chain with
# `request.endpoint_key` absent: P3 is the rule that asks about that absence.
expect(
    "a tool name that composes no key is refused 403",
    403,
    status(ENFORCE, "track_package\n", GOOD),
)
expect("it named P3, which holds on an absent key", 1, await_denial(1, P3))

block("observe: the same verdict, acted on in no way")
reset_journals()
expect("initialize is not refused", 200, handshake_status(OBSERVE))
settle()
expect("no denial was reported", 0, denials())

block("enforce with fallback block: an endpoint nobody bound is refused")
# This bundle binds only `track_package`. The status codes match
# gateway-enforce's; what differs is that the refusal names no policy.
reset_journals()
# Allowed calls reach the MCP layer, so this one needs a session.
sid = open_session(FALLBACK, GOOD) or "none"
expect(
    "the bound endpoint is judged and allowed",
    200,
    status(FALLBACK, "track_package", {"Mcp-Session-Id": sid, **GOOD}),
)
expect("the call reached the upstream", 1, forwarded_tool_calls())

reset_journals()
expect(
    "an endpoint with no binding entry is refused 403",
    403,
    status(FALLBACK, "undeclared_tool", GOOD),
)
expect("no call reached the upstream", 0, forwarded_tool_calls())
settle()
expect("the fallback refusal is reported", 1, denials())
expect("it named no policy, because none judged it", 1, denials_naming_no_policy())

block("none: a pass-through that asks the control plane nothing")
reset_journals()
expect("initialize is not refused", 200, handshake_status(PASSTHROUGH))
settle()
expect("no denial was reported", 0, denials())

block("unreachable: a gateway with no bundle still serves, on the port it was given")
expect(
    "/health answers on RAIL_GATEWAY_PORT",
    200,
    get_status("http://gateway-unreachable:9100/health"),
)
expect(
    "/ready reports no bundle held",
    503,
    get_status("http://gateway-unreachable:9100/ready"),
)

block("every request found a stub")
sweep_unmatched()
expect("no unmatched request reached the upstream", 0, lib.unmatched_upstream)
expect("no unmatched request reached rail-center", 0, lib.unmatched_rc)

finish()
