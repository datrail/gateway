"""Judge each request Apigee sends, and answer with what Apigee should change.

Apigee applies only what the returned maps contain, and writes each item of a
header returned back as a header line of its own. So the answer removes the
`x-rail` headers and sets our flow variables, and touches nothing else.
"""

import logging
import traceback
from urllib.parse import unquote

from gateway.apigee_grpc._proto.external_callout_pb2 import (
    FlowVariable,
    MessageContext,
    Strings,
)
from gateway.apigee_grpc._proto.external_callout_pb2_grpc import (
    ExternalCalloutServiceServicer,
)
from gateway.core.bundle.client import BundleHolder
from gateway.core.enforcement import PASS, DenialReporter, Verdict, judge, refusal_body
from gateway.core.keyset import KeySetHolder

log = logging.getLogger(__name__)

# The flow variables the Apigee proxy reads.
DECISION = "rail.decision"
STATUS = "rail.status"
BODY = "rail.body"
ALLOW = "allow"
REFUSE = "refuse"


class RailCallout(ExternalCalloutServiceServicer):
    """The ExternalCallout service. `holder` is None with the plugin off."""

    def __init__(
        self,
        holder: BundleHolder | None,
        reporter: DenialReporter | None,
        keyset: KeySetHolder | None = None,
    ) -> None:
        self._holder = holder
        self._reporter = reporter
        self._keyset = keyset

    async def ProcessMessage(self, request: MessageContext, context) -> MessageContext:
        # Any defect here forwards the request, as standalone does when its walk
        # raises. Escaping would be a gRPC error, which the bundle turns into 503.
        try:
            if self._keyset is not None and self._holder is not None:
                # Before the ticket is read: a `kid` not held is worth one
                # refetch, and the call waits for it rather than being refused
                # for a key that was published a moment ago.
                await self._keyset.ensure(_read_header_values(request, "x-rail"))
            return _build_answer(request, self._judge_request(request))
        except Exception as exc:  # noqa: BLE001 - logged below, without its message
            # The type and the frames only: the message could quote a header.
            log.error(
                "the callout failed (%s); allowing the request:\n%s",
                type(exc).__name__,
                "".join(traceback.format_tb(exc.__traceback__)).rstrip(),
            )
            return _build_answer(request, PASS)

    def _judge_request(self, request: MessageContext) -> Verdict:
        if self._holder is None or request.request.verb != "POST":
            return PASS
        verdict = judge(
            self._holder,
            _read_path(request.request.uri),
            request.request.content.encode(),
            _read_header_values(request, "x-rail"),
            _read_header_values(request, "x-rail-status"),
            [
                (header, value)
                for header, values in request.request.headers.items()
                for value in values.strings
            ],
            verifier=self._keyset.verifier() if self._keyset is not None else None,
        )
        if verdict.report is not None and self._reporter is not None:
            self._reporter.send(verdict.report)
        return verdict


def _read_path(uri: str) -> str:
    """The path of `uri`, without the query, percent-decoded as uvicorn does."""
    return unquote(uri.partition("?")[0]) or "/"


def _read_header_values(request: MessageContext, name: str) -> list[str] | None:
    """Every item of every header called `name`, in any case; None if none.

    Apigee splits a value on commas and sends each part as an item.
    """
    found = [
        value
        for header, values in request.request.headers.items()
        if header.lower() == name
        for value in values.strings
    ]
    return found or None


def _is_x_rail_header(name: str) -> bool:
    lowered = name.lower()
    return lowered == "x-rail" or lowered.startswith("x-rail-")


def _build_answer(request: MessageContext, verdict: Verdict) -> MessageContext:
    """The received context, with only our changes in its maps.

    Apigee's own fields are returned as received, so none of them changes.
    """
    answer = MessageContext()
    answer.CopyFrom(request)
    headers = answer.request.headers
    headers.clear()
    answer.request.form_params.clear()
    answer.request.query_params.clear()
    # An empty list removes the header. `x-rail` is always named: a header
    # that isn't there is left alone.
    headers["x-rail"].CopyFrom(Strings())
    for name in request.request.headers:
        if _is_x_rail_header(name):
            headers[name].CopyFrom(Strings())

    flow = answer.additional_flow_variables
    flow.clear()
    if verdict.status is None:
        flow[DECISION].CopyFrom(FlowVariable(string=ALLOW))
    else:
        flow[DECISION].CopyFrom(FlowVariable(string=REFUSE))
        flow[STATUS].CopyFrom(FlowVariable(string=str(verdict.status)))
        flow[BODY].CopyFrom(FlowVariable(string=refusal_body(verdict.reason).decode()))
    return answer
