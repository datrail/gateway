"""The servicer over a real `grpc.aio` channel: what it reads, what it decides,
and what it answers."""

import json
import logging
from contextlib import asynccontextmanager

import grpc
import httpx
import pytest

from core_support import (
    DENIES_ANY_TICKET,
    DENIES_EVERYTHING,
    REASONS,
    Holder,
    build_bundle,
    build_call,
    encode_ticket,
    get_enforcement_params,
)
from gateway.apigee_grpc import servicer as servicer_module
from gateway.apigee_grpc._proto.external_callout_pb2 import (
    FlowVariable,
    MessageContext,
    Request,
    Strings,
)
from gateway.apigee_grpc._proto.external_callout_pb2_grpc import (
    ExternalCalloutServiceStub,
    add_ExternalCalloutServiceServicer_to_server,
)
from gateway.apigee_grpc.servicer import BODY, DECISION, STATUS, RailCallout
from gateway.core.enforcement import DenialReporter, refusal_body


class _Reports:
    """Every denial report sent to Rail Center."""

    def __init__(self) -> None:
        self.bodies: list[dict] = []

    def receive(self, request: httpx.Request) -> httpx.Response:
        self.bodies.append(json.loads(request.content))
        return httpx.Response(202)

    def create_reporter(self) -> DenialReporter:
        return DenialReporter(
            "http://rail-center.test", {}, transport=httpx.MockTransport(self.receive)
        )


@asynccontextmanager
async def _serve(callout: RailCallout):
    """The callout on an ephemeral port, and a channel to it."""
    server = grpc.aio.server()
    add_ExternalCalloutServiceServicer_to_server(callout, server)
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()
    try:
        async with grpc.aio.insecure_channel(f"127.0.0.1:{port}") as channel:
            yield channel
    finally:
        await server.stop(None)


async def _settle(reporter: DenialReporter) -> None:
    for task in list(reporter._reports):
        await task


def _build_context(
    *,
    verb: str = "POST",
    uri: str = "/mcp",
    content: bytes = build_call(),
    headers: dict[str, list[str]] | None = None,
) -> MessageContext:
    return MessageContext(
        request=Request(
            verb=verb,
            uri=uri,
            headers={k: Strings(strings=v) for k, v in (headers or {}).items()},
            content=content.decode(),
        )
    )


def _read_flow(answer: MessageContext) -> dict[str, str]:
    return {k: v.string for k, v in answer.additional_flow_variables.items()}


def _read_headers(answer: MessageContext) -> dict[str, list[str]]:
    return {k: list(v.strings) for k, v in answer.request.headers.items()}


async def _call_once(held, context: MessageContext):
    """One `ProcessMessage`, and the reports it sent."""
    reports = _Reports()
    reporter = reports.create_reporter()
    async with _serve(RailCallout(Holder(held), reporter)) as channel:
        answer = await ExternalCalloutServiceStub(channel).ProcessMessage(context)
    await _settle(reporter)
    return answer, reports.bodies


# --- the contract table ---


@pytest.mark.asyncio
@pytest.mark.parametrize("case", get_enforcement_params("apigee-grpc"))
async def test_the_answer_and_the_report_match_every_row_of_the_contract(case):
    headers = {}
    if case.x_rail:
        headers["x-rail"] = list(case.x_rail)
    if case.x_rail_status:
        headers["x-rail-status"] = list(case.x_rail_status)
    context = _build_context(
        verb=case.method, uri=case.path, content=case.body, headers=headers
    )

    answer, sent = await _call_once(case.get_bundle(), context)

    flow = _read_flow(answer)
    if case.status is None:
        assert flow == {DECISION: "allow"}
    else:
        # The bundle's RaiseFault fails on an unset variable, so both are
        # always set on a refusal.
        assert flow == {
            DECISION: "refuse",
            STATUS: str(case.status),
            BODY: refusal_body(REASONS[case.status]).decode(),
        }
    if case.report is None:
        assert sent == []
    else:
        (body,) = sent
        body.pop("denied_at")
        assert body == case.report


# --- reading ---


@pytest.mark.asyncio
async def test_header_names_are_read_in_any_case():
    context = _build_context(headers={"X-Rail": [encode_ticket()]})

    answer, sent = await _call_once(build_bundle(DENIES_EVERYTHING), context)

    assert _read_flow(answer)[DECISION] == "allow"
    assert sent == []


@pytest.mark.asyncio
async def test_the_path_is_the_uri_without_its_query_and_decoded():
    # What the proto says `request.uri` holds: the agent's path, base path
    # included, with its query.
    context = _build_context(uri="/v1/mcp%20proxy/mcp?session=1&x=%2F")

    _, sent = await _call_once(build_bundle(DENIES_EVERYTHING), context)

    assert sent[0]["endpoint_key"] == "/v1/mcp proxy/mcp#tools/call#track_package"


@pytest.mark.asyncio
async def test_with_the_plugin_off_everything_is_allowed_and_x_rail_still_removed():
    context = _build_context(headers={"x-rail-status": ["forged"]})
    async with _serve(RailCallout(None, None)) as channel:
        answer = await ExternalCalloutServiceStub(channel).ProcessMessage(context)

    assert _read_flow(answer) == {DECISION: "allow"}
    assert _read_headers(answer) == {"x-rail": [], "x-rail-status": []}


# --- answering ---


@pytest.mark.asyncio
async def test_the_answer_holds_no_header_but_the_removals():
    """Apigee writes back only the last item of a returned header, so
    returning `accept` would break it. Every map is empty but the removals."""
    context = _build_context(
        headers={
            "accept": ["application/json", "text/event-stream"],
            "authorization": ["Bearer agent-secret"],
            "X-Rail-Foo": ["forged"],
        }
    )
    context.request.query_params["q"].strings.append("1")
    context.request.form_params["f"].strings.append("2")
    context.additional_flow_variables["apigee.own"].CopyFrom(FlowVariable(string="x"))

    answer, _ = await _call_once(build_bundle(), context)

    assert _read_headers(answer) == {"x-rail": [], "X-Rail-Foo": []}
    assert dict(answer.request.query_params) == {}
    assert dict(answer.request.form_params) == {}
    assert _read_flow(answer) == {DECISION: "allow"}


@pytest.mark.asyncio
async def test_x_rail_is_removed_even_when_the_agent_sent_none():
    answer, _ = await _call_once(build_bundle(), _build_context())

    assert _read_headers(answer) == {"x-rail": []}


@pytest.mark.asyncio
async def test_the_content_and_apigees_fields_are_returned_as_received():
    context = _build_context()
    context.message_id = "m-1"
    context.proxy.base_path = "/v1"

    answer, _ = await _call_once(build_bundle(), context)

    assert answer.request.content == context.request.content
    assert answer.request.uri == context.request.uri
    assert answer.message_id == "m-1"
    assert answer.proxy.base_path == "/v1"


# --- logging ---


@pytest.mark.asyncio
async def test_no_header_value_is_logged(caplog):
    secret = "Bearer agent-secret"
    ticket = encode_ticket()
    context = _build_context(
        headers={"authorization": [secret], "x-rail": [ticket]},
    )

    with caplog.at_level(logging.DEBUG):
        answer, sent = await _call_once(build_bundle(DENIES_ANY_TICKET), context)

    assert _read_flow(answer)[DECISION] == "refuse"
    assert len(sent) == 1
    assert secret not in caplog.text
    assert ticket not in caplog.text


@pytest.mark.asyncio
async def test_a_failure_in_the_servicer_allows_the_request(caplog, monkeypatch):
    """Any defect forwards the request. The traceback is logged; the
    exception's message isn't, since it could quote a header."""
    ticket = encode_ticket()

    def explode(*_args, **_kwargs):
        raise RuntimeError(f"a defect holding {ticket}")

    monkeypatch.setattr(servicer_module, "judge", explode)
    context = _build_context(headers={"x-rail": [ticket]})

    with caplog.at_level(logging.ERROR):
        answer, sent = await _call_once(build_bundle(DENIES_EVERYTHING), context)

    assert _read_flow(answer) == {DECISION: "allow"}
    assert _read_headers(answer) == {"x-rail": []}
    assert sent == []
    assert "the callout failed (RuntimeError)" in caplog.text
    assert "explode" in caplog.text, "the traceback is logged"
    assert ticket not in caplog.text
