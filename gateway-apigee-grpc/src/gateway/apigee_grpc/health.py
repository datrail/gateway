"""A health probe: ask the callout's gRPC health service on this host.

    python -m gateway.apigee_grpc.health [--ready]

Asks liveness, or readiness with `--ready`, on `RAIL_GATEWAY_PORT`. Exits 0
when the answer is `SERVING`, and 1 otherwise.
"""

import argparse
import sys

import grpc
from grpc_health.v1 import health_pb2, health_pb2_grpc

from gateway.apigee_grpc.server import READY_SERVICE
from gateway.core.settings import port

_TIMEOUT_SECONDS = 5.0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m gateway.apigee_grpc.health")
    parser.add_argument("--ready", action="store_true", help="ask readiness")
    service = READY_SERVICE if parser.parse_args(argv).ready else ""
    try:
        with grpc.insecure_channel(f"localhost:{port()}") as channel:
            answer = health_pb2_grpc.HealthStub(channel).Check(
                health_pb2.HealthCheckRequest(service=service),
                timeout=_TIMEOUT_SECONDS,
            )
    except grpc.RpcError as exc:
        print(f"no answer: {exc.code().name}", file=sys.stderr)
        return 1
    status = health_pb2.HealthCheckResponse.ServingStatus.Name(answer.status)
    print(status)
    return 0 if answer.status == health_pb2.HealthCheckResponse.SERVING else 1


if __name__ == "__main__":
    sys.exit(main())
