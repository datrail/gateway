"""The callout's process: health, readiness, the message limit, and how it
starts and stops."""

import asyncio
import os
import signal
import socket
import subprocess
import sys
import time
from contextlib import asynccontextmanager

import grpc
import httpx
import pytest
from grpc_health.v1 import health_pb2, health_pb2_grpc

from gateway.apigee_grpc import probe_health
from gateway.apigee_grpc._proto.external_callout_pb2 import MessageContext, Request
from gateway.apigee_grpc._proto.external_callout_pb2_grpc import (
    ExternalCalloutServiceStub,
)
from gateway.apigee_grpc.server import READY_SERVICE, serving
from gateway.core.bundle.client import BundleHolder

_SERVING = health_pb2.HealthCheckResponse.SERVING
_NOT_SERVING = health_pb2.HealthCheckResponse.NOT_SERVING
_MB = 1024 * 1024
_BUNDLE = {
    "schema_version": "1.0",
    "content_hash": "v1",
    "policies": [
        {"id": "5c8f1e42-0000-4000-8000-0000000000a1", "name": "P", "priority": 1}
    ],
    "bindings": [],
}


def _create_holder(answer) -> BundleHolder:
    """A holder whose Rail Center is `answer`, asked once per fetch."""
    return BundleHolder(
        "http://rail-center.test",
        {},
        "edge",
        interval_seconds=3600,
        transport=httpx.MockTransport(lambda _request: answer()),
    )


def _answer_unreachable() -> httpx.Response:
    return httpx.Response(503)


def _answer_with_a_bundle() -> httpx.Response:
    return httpx.Response(200, json=_BUNDLE)


async def _check(channel, service: str = "") -> int:
    stub = health_pb2_grpc.HealthStub(channel)
    answer = await stub.Check(health_pb2.HealthCheckRequest(service=service))
    return answer.status


@asynccontextmanager
async def _open_channel(holder, *, max_message_bytes: int = 16 * _MB):
    """The callout served on a free port, and a channel to it."""
    async with (
        serving(
            holder, None, listen_port=0, max_message_bytes=max_message_bytes
        ) as port,
        grpc.aio.insecure_channel(f"127.0.0.1:{port}") as channel,
    ):
        yield channel


# --- health and readiness ---


@pytest.mark.asyncio
async def test_with_rail_center_reachable_it_is_live_and_ready():
    async with _open_channel(_create_holder(_answer_with_a_bundle)) as channel:
        assert await _check(channel) == _SERVING
        assert await _check(channel, READY_SERVICE) == _SERVING


@pytest.mark.asyncio
async def test_with_rail_center_unreachable_it_is_live_and_not_ready():
    async with _open_channel(_create_holder(_answer_unreachable)) as channel:
        assert await _check(channel) == _SERVING
        assert await _check(channel, READY_SERVICE) == _NOT_SERVING


@pytest.mark.asyncio
async def test_it_becomes_ready_when_the_first_bundle_arrives():
    answer = {"now": _answer_unreachable}
    holder = _create_holder(lambda: answer["now"]())
    async with _open_channel(holder) as channel:
        assert await _check(channel, READY_SERVICE) == _NOT_SERVING

        answer["now"] = _answer_with_a_bundle
        await holder.refresh()

        assert await _check(channel, READY_SERVICE) == _SERVING


@pytest.mark.asyncio
async def test_with_the_plugin_off_it_is_ready_at_once():
    async with _open_channel(None) as channel:
        assert await _check(channel, READY_SERVICE) == _SERVING


@pytest.mark.asyncio
async def test_an_unknown_health_service_is_not_found():
    async with _open_channel(None) as channel:
        with pytest.raises(grpc.aio.AioRpcError) as failed:
            await _check(channel, "something.else")
    assert failed.value.code() == grpc.StatusCode.NOT_FOUND


# --- the message limit ---


def _build_context(content_bytes: int) -> MessageContext:
    return MessageContext(
        request=Request(verb="POST", uri="/mcp", content="x" * content_bytes)
    )


@pytest.mark.asyncio
async def test_a_message_under_the_limit_is_answered():
    async with _open_channel(None, max_message_bytes=_MB) as channel:
        stub = ExternalCalloutServiceStub(channel)
        answer = await stub.ProcessMessage(_build_context(_MB - 1024))
    assert len(answer.request.content) == _MB - 1024


@pytest.mark.asyncio
async def test_a_message_exactly_at_the_limit_is_answered():
    # The answer is larger than the request, so the send limit needs headroom.
    context = _build_context(_MB)
    context.request.content = "x" * (_MB - (context.ByteSize() - _MB))
    assert context.ByteSize() == _MB

    async with _open_channel(None, max_message_bytes=_MB) as channel:
        answer = await ExternalCalloutServiceStub(channel).ProcessMessage(context)
    assert answer.ByteSize() > _MB


@pytest.mark.asyncio
async def test_a_message_over_the_limit_is_refused_before_the_servicer():
    async with _open_channel(None, max_message_bytes=_MB) as channel:
        stub = ExternalCalloutServiceStub(channel)
        with pytest.raises(grpc.aio.AioRpcError) as failed:
            await stub.ProcessMessage(_build_context(_MB + 1))
    assert failed.value.code() == grpc.StatusCode.RESOURCE_EXHAUSTED
    assert "Received message larger than max" in failed.value.details()


# --- the process ---


def _find_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _create_environment(**settings: str) -> dict[str, str]:
    """This process's environment, without any `RAIL_` variable, plus
    `settings`."""
    kept = {k: v for k, v in os.environ.items() if not k.startswith("RAIL_")}
    return {**kept, **settings}


def _start_callout(env: dict[str, str]) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-m", "gateway.apigee_grpc"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


async def _wait_until_live(port: int) -> None:
    deadline = time.monotonic() + 10
    async with grpc.aio.insecure_channel(f"127.0.0.1:{port}") as channel:
        while True:
            try:
                if await _check(channel) == _SERVING:
                    return
            except grpc.aio.AioRpcError:
                if time.monotonic() > deadline:
                    raise
            await asyncio.sleep(0.05)


@pytest.mark.parametrize(
    ("settings", "named"),
    [
        (
            {"RAIL_GATEWAY_GRPC_MAX_MESSAGE_MB": "lots"},
            "RAIL_GATEWAY_GRPC_MAX_MESSAGE_MB must be an integer",
        ),
        ({"RAIL_GATEWAY_PORT": "0x50"}, "RAIL_GATEWAY_PORT must be an integer"),
        ({"RAIL_PLUGIN_ENABLED": "true"}, "RAIL_CENTER_URL is required"),
        # Before logging is configured.
        ({"RAIL_GATEWAY_LOG_LEVEL": "LOUD"}, "RAIL_GATEWAY_LOG_LEVEL must be one of"),
    ],
    ids=["message limit", "port", "plugin on with no Rail Center", "log level"],
)
def test_a_configuration_error_exits_2_before_serving(settings, named):
    callout = _start_callout(_create_environment(**settings))
    output, _ = callout.communicate(timeout=10)

    assert callout.returncode == 2, output
    assert named in output
    assert "Traceback" not in output
    assert "serving the ExternalCallout service" not in output


@pytest.mark.asyncio
@pytest.mark.parametrize("plugin", [False, True], ids=["plugin off", "plugin on"])
async def test_sigterm_stops_it_cleanly(plugin):
    """One loop runs the server, the holder and its refresh loop, and SIGTERM
    stops them all. With the plugin on, Rail Center is a closed port."""
    port = _find_free_port()
    settings = {"RAIL_GATEWAY_PORT": str(port)}
    if plugin:
        settings |= {
            "RAIL_PLUGIN_ENABLED": "true",
            "RAIL_CENTER_URL": f"http://127.0.0.1:{_find_free_port()}",
            "RAIL_GATEWAY_SLUG": "edge",
        }
    callout = _start_callout(_create_environment(**settings))
    try:
        await _wait_until_live(port)
        callout.send_signal(signal.SIGTERM)
        output, _ = await asyncio.to_thread(callout.communicate, timeout=10)
    finally:
        callout.kill()

    assert callout.returncode == 0, output
    assert f"serving the ExternalCallout service on port {port}" in output
    assert "stopping" in output
    assert "Traceback" not in output


# --- the health probe ---


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("answer", "args", "exit_code"),
    [
        (_answer_unreachable, [], 0),
        (_answer_unreachable, ["--ready"], 1),
        (_answer_with_a_bundle, ["--ready"], 0),
    ],
    ids=["live", "not ready", "ready"],
)
async def test_the_probe_exits_0_only_when_serving(
    monkeypatch, answer, args, exit_code
):
    async with serving(
        _create_holder(answer), None, listen_port=0, max_message_bytes=_MB
    ) as port:
        monkeypatch.setenv("RAIL_GATEWAY_PORT", str(port))
        assert await asyncio.to_thread(probe_health.main, args) == exit_code


def test_the_probe_exits_1_when_nothing_answers(monkeypatch):
    monkeypatch.setenv("RAIL_GATEWAY_PORT", str(_find_free_port()))
    assert probe_health.main([]) == 1
