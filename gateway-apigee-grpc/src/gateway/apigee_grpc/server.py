"""The callout's process: settings, the holder, and the gRPC server."""

import asyncio
import logging
import signal
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import grpc
from grpc_health.v1 import health, health_pb2, health_pb2_grpc

from gateway.apigee_grpc._proto.external_callout_pb2_grpc import (
    add_ExternalCalloutServiceServicer_to_server,
)
from gateway.apigee_grpc.servicer import RailCallout
from gateway.apigee_grpc.settings import get_max_message_bytes
from gateway.core.bundle.client import BundleHolder
from gateway.core.enforcement import DenialReporter
from gateway.core.lifecycle import is_ready, running
from gateway.core.logs import configure_logging
from gateway.core.mode import describe_plugin, plugin_enabled
from gateway.core.settings import build_holder, port, rail_center_from_environment

_log = logging.getLogger(__name__)

# The gRPC health service that reports readiness. The empty name is liveness.
READY_SERVICE = "datrail.gateway.Ready"
# How long a stopping server lets calls in flight finish.
_STOP_GRACE_SECONDS = 5.0
# The answer echoes the content plus our flow variables and removals, so it can
# be larger than the request: this lets anything received be answered.
_SEND_HEADROOM_BYTES = 64 * 1024

_SERVING = health_pb2.HealthCheckResponse.SERVING
_NOT_SERVING = health_pb2.HealthCheckResponse.NOT_SERVING


class _Health(health.aio.HealthServicer):
    """gRPC health, with readiness read from the holder on every check."""

    def __init__(self, holder: BundleHolder | None) -> None:
        super().__init__()
        self._holder = holder

    async def Check(self, request, context):
        if request.service == READY_SERVICE:
            await self._update_readiness()
        return await super().Check(request, context)

    async def _update_readiness(self) -> None:
        # `set` also tells anyone watching.
        await self.set(
            READY_SERVICE, _SERVING if is_ready(self._holder) else _NOT_SERVING
        )


@asynccontextmanager
async def serving(
    holder: BundleHolder | None,
    reporter: DenialReporter | None,
    *,
    listen_port: int,
    max_message_bytes: int,
) -> AsyncIterator[int]:
    """Serve the callout on `listen_port` (0: any free port) for the life of the
    block, yielding the bound port. `holder` is None with the plugin off."""
    async with running(holder):
        server = grpc.aio.server(
            options=[
                ("grpc.max_receive_message_length", max_message_bytes),
                (
                    "grpc.max_send_message_length",
                    max_message_bytes + _SEND_HEADROOM_BYTES,
                ),
            ]
        )
        add_ExternalCalloutServiceServicer_to_server(
            RailCallout(holder, reporter), server
        )
        health = _Health(holder)
        health_pb2_grpc.add_HealthServicer_to_server(health, server)
        bound = server.add_insecure_port(f"0.0.0.0:{listen_port}")
        await server.start()
        await health.set("", _SERVING)
        await health._update_readiness()
        try:
            yield bound
        finally:
            await health.enter_graceful_shutdown()
            await server.stop(_STOP_GRACE_SECONDS)


async def _serve_until_stopped(
    holder: BundleHolder | None,
    reporter: DenialReporter | None,
    listen_port: int,
    max_message_bytes: int,
) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, stop.set)
    async with serving(
        holder, reporter, listen_port=listen_port, max_message_bytes=max_message_bytes
    ) as bound:
        _log.info("serving the ExternalCallout service on port %d", bound)
        await stop.wait()
        _log.info("stopping")


def main() -> None:
    """Read the settings, then serve until SIGTERM. A configuration error
    raises before anything is served."""
    configure_logging()
    enabled = plugin_enabled()
    _log.info("%s", describe_plugin(enabled))
    holder = build_holder() if enabled else None
    reporter = DenialReporter(*rail_center_from_environment()) if enabled else None
    listen_port = port()
    max_message_bytes = get_max_message_bytes()
    _log.info("gRPC messages are limited to %d bytes", max_message_bytes)
    asyncio.run(_serve_until_stopped(holder, reporter, listen_port, max_message_bytes))
