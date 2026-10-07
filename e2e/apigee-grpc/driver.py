"""Checks the callout's image: it starts, answers gRPC health and judges a call."""

import json
import os

import grpc
from grpc_health.v1 import health_pb2, health_pb2_grpc
from lib import (
    RAIL_CENTER,
    await_denial,
    block,
    bundle_fetches,
    expect,
    finish,
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


block("the image runs as its own user")
expect("the uid is 10001", 10001, os.getuid())

block("enrolled: holds the enforce bundle and judges a call")
expect("a bundle was fetched at startup", 1, wait_for(bundle_fetches, 1))
expect("liveness", "SERVING", _check_health("callout:8080"))
expect("readiness", "SERVING", _check_health("callout:8080", "datrail.gateway.Ready"))
expect("a GET is allowed", "allow", _process("callout:8080", "GET")["rail.decision"])
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

finish()
