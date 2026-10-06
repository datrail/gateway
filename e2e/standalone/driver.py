"""Drives each standalone gateway and asserts what crossed the wire."""

import os
import time

import lib
from lib import (
    await_denial,
    block,
    bundle_fetches,
    call_tool,
    denials,
    denials_naming_no_policy,
    expect,
    fail,
    finish,
    forwarded_tool_calls,
    handshake_status,
    ok,
    open_session,
    reset_journals,
    status,
    sweep_unmatched,
    wait_for,
)

GOOD = {"x-rail": os.environ["GOOD_TICKET"]}
LOW_SCORE = {"x-rail": os.environ["LOW_SCORE_TICKET"]}

P0 = "11111111-0000-4000-8000-000000000000"
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
expect("it named P0, the rule that matched", 1, await_denial(1, P0))
# Catches a second report naming another rule, which the scoped count misses.
settle()
expect("exactly one denial was reported", 1, denials())

block(
    "enforce: a low-posture ticket opens a session and is stopped at its first call too"
)
reset_journals()
expect("initialize is not refused", 200, handshake_status(ENFORCE, LOW_SCORE))
expect("the call is refused 403", 403, status(ENFORCE, "track_package", LOW_SCORE))
expect("it named P1, not P0", 1, await_denial(1, P1))

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
# P2 (`endpoint_key`) and P3 (`skill_match`) are dropped from a keyless chain.
# P3 holds against an absent key, so keeping it would refuse the handshake.
reset_journals()
sid = open_session(ENFORCE, GOOD) or "none"
expect("the handshake still succeeds", 1, 1 if sid != "none" else 0)
expect(
    "the forbidden call is refused 403",
    403,
    status(ENFORCE, "forbidden_tool", {"Mcp-Session-Id": sid, **GOOD}),
)
expect("it named P2, the endpoint rule", 1, await_denial(1, P2))
# A control character composes no key but keeps the full chain: only a rule that
# holds against an absent key, like P3, can refuse it. Pins what P3 is.
expect(
    "a tool name that composes no key is refused 403",
    403,
    status(ENFORCE, "track_package\n", GOOD),
)
expect("it named P3, which holds against an absent key", 1, await_denial(1, P3))

block("enforce: a call the ticket declares no skill for is denied by P3")
# Any tool but `track_package` (declared) and `forbidden_tool` (P2's).
reset_journals()
expect(
    "the unskilled call is refused 403", 403, status(ENFORCE, "undeclared_tool", GOOD)
)
expect("it named P3, the skill rule", 1, await_denial(1, P3))

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

block("every request found a stub")
sweep_unmatched()
expect("no unmatched request reached the upstream", 0, lib.unmatched_upstream)
expect("no unmatched request reached rail-center", 0, lib.unmatched_rc)

finish()
