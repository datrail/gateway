"""A stand-in for an Apigee proxy running the reference bundle, for the e2e stack.

A model, not Apigee: it does what the bundle, Apigee's docs and the live
harness's runs (DR-147 plan, §9) say Apigee does, and nothing else. Each rule
says where it comes from. Settings, from the environment:

- APIGEE_PROXIES: `<base path>=<callout host:port>`, comma-separated;
- APIGEE_TARGET_URL: where an allowed request goes, the base path replaced;
- APIGEE_TIMEOUT_MS: EC-Rail's TimeoutMs;
- APIGEE_BUNDLE: the reference bundle's `apiproxy/` folder.
"""

import http.client
import os
import urllib.parse
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import grpc

from gateway.apigee_grpc._proto.external_callout_pb2 import (
    MessageContext,
    Request,
    Strings,
)
from gateway.apigee_grpc._proto.external_callout_pb2_grpc import (
    ExternalCalloutServiceStub,
)
from gateway.apigee_grpc.servicer import BODY, DECISION, REFUSE, STATUS

_PROXIES = dict(
    entry.split("=", 1) for entry in os.environ["APIGEE_PROXIES"].split(",")
)
_TARGET = urllib.parse.urlsplit(os.environ["APIGEE_TARGET_URL"])
_TIMEOUT_SECONDS = int(os.environ.get("APIGEE_TIMEOUT_MS", "5000")) / 1000
# The bundle's own 503, so the two can't drift.
_CALLOUT_FAILED = (
    ET.parse(
        os.path.join(os.environ["APIGEE_BUNDLE"], "policies", "RF-CalloutFailed.xml")
    )
    .getroot()
    .findtext("FaultResponse/Set/Payload")
    .encode()
)
# Set per hop, never forwarded.
_HOP_HEADERS = {"connection", "content-length", "host", "transfer-encoding"}


def _find_proxy(path):
    """The base path and callout serving `path`, or None."""
    for base, callout in _PROXIES.items():
        if path == base or path.startswith(base + "/"):
            return base, callout
    return None


def _split_headers(lines):
    """Each header's items, by name as first received, as the callout sees them.
    Apigee splits values on commas (prototype; live §9 #1, #2), and a repeated
    line adds items."""
    headers = {}
    for name, value in lines:
        key = next((k for k in headers if k.lower() == name.lower()), name)
        headers.setdefault(key, []).extend(item.strip() for item in value.split(","))
    return headers


def _call_callout(callout, verb, uri, headers, body):
    """The callout's answer, or None for any failure: unreachable, timed out,
    a gRPC error, or an answer over gRPC's 4 MiB default (live §9 #8)."""
    context = MessageContext(
        request=Request(
            verb=verb,
            uri=uri,
            headers={name: Strings(strings=items) for name, items in headers.items()},
            # Apigee sends a body that isn't UTF-8, replaced (live §9 #6).
            content=body.decode(errors="replace"),
        )
    )
    try:
        with grpc.insecure_channel(callout) as channel:
            return ExternalCalloutServiceStub(channel).ProcessMessage(
                context, timeout=_TIMEOUT_SECONDS
            )
    except grpc.RpcError:
        return None


def _apply_answer(lines, answer):
    """The header lines after the answer. One not returned is left as received
    (live: `accept` arrives whole); an empty list removes it (docs); each item
    of any other is written back as a line of its own (live, step 17)."""
    for name, values in answer.request.headers.items():
        lines = [line for line in lines if line[0].lower() != name.lower()]
        lines += [(name, item) for item in values.strings]
    return lines


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def do_DELETE(self):
        self._handle()

    def _handle(self):
        path, _, query = self.path.partition("?")
        proxy = _find_proxy(path)
        if proxy is None:
            self._answer(404, {}, b"")
            return
        base, callout = proxy
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        lines = [
            (name, value)
            for name, value in self.headers.items()
            if name.lower() not in _HOP_HEADERS
        ]

        # EC-Rail: `uri` is the path with the query, as sent (live §9 #5).
        answer = _call_callout(
            callout, self.command, self.path, _split_headers(lines), body
        )
        flow = answer.additional_flow_variables if answer is not None else {}
        # The FaultRule: no decision means the callout failed (D2).
        if DECISION not in flow:
            self._answer(503, {"Content-Type": ["application/json"]}, _CALLOUT_FAILED)
            return
        if flow[DECISION].string == REFUSE:
            # RF-Refuse (live §9 #3).
            self._answer(
                int(flow[STATUS].string),
                {"Content-Type": ["application/json"]},
                flow[BODY].string.encode(),
            )
            return

        # The answer's content is the body forwarded, even empty (live §9 #4).
        self._forward(
            path[len(base) :],
            query,
            _apply_answer(lines, answer),
            answer.request.content.encode(),
        )

    def _forward(self, suffix, query, lines, body):
        """Send the request to the target, and its answer back as received."""
        if _TARGET.scheme == "https":
            connection = http.client.HTTPSConnection(_TARGET.netloc, timeout=60)
        else:
            connection = http.client.HTTPConnection(_TARGET.netloc, timeout=60)
        try:
            connection.putrequest(
                self.command, _TARGET.path + suffix + (f"?{query}" if query else "")
            )
            for name, value in lines:
                connection.putheader(name, value)
            connection.putheader("Content-Length", str(len(body)))
            connection.endheaders(body)
            response = connection.getresponse()
            received = {}
            for name, value in response.getheaders():
                if name.lower() not in _HOP_HEADERS:
                    received.setdefault(name, []).append(value)
            self._answer(response.status, received, response.read())
        except OSError:
            self._answer(502, {}, b"")
        finally:
            connection.close()

    def _answer(self, status, headers, body):
        self.send_response(status)
        for name, values in headers.items():
            for value in values:
                self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), _Handler).serve_forever()
