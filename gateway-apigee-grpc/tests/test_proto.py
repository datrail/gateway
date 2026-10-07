"""The generated code imports from inside the package, and speaks Apigee's wire
names."""

from gateway.apigee_grpc._proto.external_callout_pb2 import (
    DESCRIPTOR,
    MessageContext,
    Request,
    Strings,
)
from gateway.apigee_grpc._proto.external_callout_pb2_grpc import (
    ExternalCalloutServiceServicer,
)


def test_a_message_context_survives_the_wire():
    sent = MessageContext(
        request=Request(
            verb="POST",
            uri="/mcp",
            headers={"x-rail": Strings(strings=["one", "two"])},
            content='{"method": "tools/call"}',
        )
    )

    received = MessageContext.FromString(sent.SerializeToString())

    assert received == sent
    assert list(received.request.headers["x-rail"].strings) == ["one", "two"]


def test_the_service_keeps_apigees_wire_name():
    # The proto's path in this repo must not reach the wire.
    service = DESCRIPTOR.services_by_name["ExternalCalloutService"]
    assert service.full_name == "apigee.ExternalCalloutService"
    assert hasattr(ExternalCalloutServiceServicer, "ProcessMessage")
