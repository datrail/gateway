"""Checks the callout through the reference bundle: live, on real Apigee;
locally, on the stand-in (apigee_standin.py), after the image's own checks.

E2E_TARGET picks which: `local` (the default, in compose.yml) or `live`
(`live/session.sh test`).
"""

import json
import os

import grpc
import lib
from grpc_health.v1 import health_pb2, health_pb2_grpc
from lib import (
    RAIL_CENTER,
    UPSTREAM,
    await_denial,
    await_last_denial,
    block,
    bundle_fetches,
    call_tool,
    count_upstream_requests,
    expect,
    fail,
    finish,
    forwarded_tool_calls,
    get_received_headers,
    handshake_status,
    ok,
    open_session,
    reset_journals,
    send_raw_post,
    status,
    sweep_unmatched,
    unmatched,
    wait_for,
)

from gateway.apigee_grpc._proto.external_callout_pb2 import (
    MessageContext,
    Request,
)
from gateway.apigee_grpc._proto.external_callout_pb2_grpc import (
    ExternalCalloutServiceStub,
)

P0 = "11111111-0000-4000-8000-000000000000"
P2 = "11111111-0000-4000-8000-000000000002"
CALL = {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "x"}}


def _check_health(target, service=""):
    """The status name, or the gRPC error's code."""
    with grpc.insecure_channel(target) as channel:
        stub = health_pb2_grpc.HealthStub(channel)
        try:
            answer = stub.Check(
                health_pb2.HealthCheckRequest(service=service), timeout=5
            )
        except grpc.RpcError as error:
            return error.code().name
    return health_pb2.HealthCheckResponse.ServingStatus.Name(answer.status)


def _process(target, verb, content=""):
    """The flow variables the callout set."""
    context = MessageContext(request=Request(verb=verb, uri="/mcp", content=content))
    with grpc.insecure_channel(target) as channel:
        answer = ExternalCalloutServiceStub(channel).ProcessMessage(context, timeout=5)
    return {k: v.string for k, v in answer.additional_flow_variables.items()}


# A fake agent credential: Apigee must forward it as sent (D3).
_AGENT = {"Authorization": "Bearer e2e-agent"}
_REFUSED = '{"error": "denied by policy"}'
_CALLOUT_FAILED = '{"error": "policy ruleset cannot be applied"}'
_CALL = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {"name": "track_package"},
    }
).encode()


def _run_apigee_cases(enforce, no_callout):
    good = {"x-rail": os.environ["E2E_GOOD_TICKET"], **_AGENT}

    block("enforce: discovery passes, and a call with no ticket is refused")
    reset_journals()
    expect("initialize is not refused", 200, handshake_status(enforce, _AGENT))
    code, body = call_tool(enforce, "track_package", headers=_AGENT)
    expect("the call is refused 403", 403, code)
    expect("with standalone's body", _REFUSED, body)
    expect("no call reached the upstream", 0, forwarded_tool_calls())
    expect("the denial names P0", 1, await_denial(1, P0))

    block("enforce: a good ticket is forwarded, with only the agent's headers")
    reset_journals()
    sid = open_session(enforce, good)
    if sid is None:
        fail("the handshake did not return a session id")
        sid = "none"
    code, body = call_tool(
        enforce,
        "track_package",
        {"tracking_number": "pkg-1"},
        {"Mcp-Session-Id": sid, "x-rail-status": "not-found", **good},
        request_id=2,
    )
    if code == 200 and '"text":"delivered"' in body:
        ok("the tool call returns the upstream answer")
    else:
        fail(f"the tool call returns the upstream answer — got {code} {body}")
    received = (get_received_headers(UPSTREAM) or [{}])[0]
    expect(
        "no x-rail* header reaches the upstream",
        "[]",
        sorted(name for name in received if name.startswith("x-rail")),
    )
    expect(
        "accept reaches it whole",
        "application/json, text/event-stream",
        received.get("accept"),
    )
    expect(
        "the agent's Authorization reaches it as sent",
        "Bearer e2e-agent",
        received.get("authorization"),
    )

    block("enforce: a ticket Apigee splits on its comma is undecodable")
    reset_journals()
    split = {**good, "x-rail": os.environ["E2E_GOOD_TICKET"] + ",x"}
    expect(
        "the call is refused 403",
        403,
        call_tool(enforce, "track_package", headers=split)[0],
    )
    expect(
        "the denial reads the ticket as undecodable",
        "undecodable",
        await_last_denial().get("metadata", {}).get("x-rail-status"),
    )

    # §9 #1: standalone refuses a ticket sent twice.
    block("enforce: a ticket sent on two header lines is undecodable")
    reset_journals()
    ticket = os.environ["E2E_GOOD_TICKET"]
    code, _ = send_raw_post(
        enforce, _CALL, [("x-rail", ticket), ("x-rail", ticket), *_AGENT.items()]
    )
    expect("the call is refused 403", 403, code)
    expect(
        "the denial reads the ticket as undecodable",
        "undecodable",
        await_last_denial().get("metadata", {}).get("x-rail-status"),
    )

    # §9 #2: Apigee splits the claim on its comma, so it reads as two and is
    # dropped; standalone records it whole. No real claim has a comma.
    block("enforce: a claimed status with a comma is dropped")
    reset_journals()
    claimed = {"x-rail-status": "not-found, expired", **_AGENT}
    expect("the call is refused 403", 403, status(enforce, "track_package", claimed))
    expect(
        "the denial records no claim",
        "<none>",
        await_last_denial().get("metadata", {}).get("claimed-x-rail-status", "<none>"),
    )

    # §9 #5: the endpoint key is the path without the query.
    block("enforce: the query string stays out of the endpoint key")
    reset_journals()
    expect(
        "the forbidden call is refused 403",
        403,
        status(enforce + "?e2e=1", "forbidden_tool", good),
    )
    expect("it named P2, the endpoint rule", 1, await_denial(1, P2))

    # §9 #6: whether Apigee sends such content, and what then answers.
    block("enforce: a body that isn't UTF-8 never reaches the upstream")
    reset_journals()
    code, body = send_raw_post(
        enforce, b"\xff\xfe{}", [("x-rail", ticket), *_AGENT.items()]
    )
    if code in (403, 503):
        ok(f"the call is refused ({code}: {body})")
    else:
        fail(f"the call is refused 403 or 503 — got {code} {body}")
    expect("nothing reached the upstream", 0, count_upstream_requests())

    # §9 #8: Apigee accepts a callout answer of at most 4 MiB, and the answer
    # echoes the body, so a larger call fails as if the callout were down.
    block("enforce: a 3.5 MiB call is forwarded, a 5 MiB one fails closed")
    reset_journals()
    code, body = call_tool(
        enforce, "track_package", {"pad": "x" * 7 * 512 * 1024}, good
    )
    if code == 200 and '"text":"delivered"' in body:
        ok("the 3.5 MiB call returns the upstream answer")
    else:
        fail(f"the 3.5 MiB call returns the upstream answer — got {code} {body[:300]}")
    reset_journals()
    code, body = call_tool(
        enforce, "track_package", {"pad": "x" * 5 * 1024 * 1024}, good
    )
    expect("the 5 MiB call is answered 503", 503, code)
    expect("with RF-CalloutFailed's body", _CALLOUT_FAILED, body)
    expect("nothing reached the upstream", 0, count_upstream_requests())

    block("no-callout: the proxy fails closed (D2)")
    reset_journals()
    code, body = call_tool(no_callout, "track_package", headers=good)
    expect("the call is answered 503", 503, code)
    expect("with RF-CalloutFailed's body", _CALLOUT_FAILED, body)
    expect("nothing reached the upstream", 0, count_upstream_requests())

    block("every request found a stub")
    sweep_unmatched()
    expect("no unmatched request reached the upstream", 0, lib.unmatched_upstream)
    expect("no unmatched request reached rail-center", 0, lib.unmatched_rc)


# The stub stack's cases: the image, its health and its port.
def _run_local_cases():
    block("the image runs as its own user")
    expect("the uid is 10001", 10001, os.getuid())

    block("enrolled: holds the enforce bundle and judges a call")
    expect("a bundle was fetched at startup", 1, wait_for(bundle_fetches, 1))
    expect("liveness", "SERVING", _check_health("callout:8080"))
    expect(
        "readiness", "SERVING", _check_health("callout:8080", "datrail.gateway.Ready")
    )
    expect(
        "a GET is allowed", "allow", _process("callout:8080", "GET")["rail.decision"]
    )
    refused = _process("callout:8080", "POST", json.dumps(CALL))
    expect("a call with no ticket is refused", "refuse", refused.get("rail.decision"))
    expect("with 403", "403", refused.get("rail.status"))
    expect(
        "and standalone's body",
        '{"error": "denied by policy"}',
        refused.get("rail.body"),
    )
    expect("the denial is reported, naming P0", 1, await_denial(1, P0))

    block("unreachable: serves on the port it was given, and isn't ready")
    expect("liveness on 9100", "SERVING", _check_health("callout-unreachable:9100"))
    expect(
        "readiness on 9100",
        "NOT_SERVING",
        _check_health("callout-unreachable:9100", "datrail.gateway.Ready"),
    )

    block("every request found a stub")
    expect("no unmatched request reached rail-center", 0, unmatched(RAIL_CENTER))


if os.environ.get("E2E_TARGET", "local") == "live":
    _run_apigee_cases(os.environ["E2E_ENFORCE_URL"], os.environ["E2E_NO_CALLOUT_URL"])
else:
    # First: the Apigee cases reset the journals, and these count a startup fetch.
    _run_local_cases()
    _run_apigee_cases("http://apigee:8080/mcp", "http://apigee:8080/no-callout")
finish()
