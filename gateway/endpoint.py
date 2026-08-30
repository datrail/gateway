"""Resolve an MCP call to the endpoint key the control plane registered.

The key is ``<RAIL_DATASOURCE_SLUG>.<tool_name>`` — ``delivery.track_package`` —
and this gateway is structurally the only party that can compose it. MCP hides a
call's identity in the message rather than the URL: every request is ``POST
/mcp``, so nothing an enforcement point could match on is visible from the
outside. Rail Center never sees the request, and the caller never knows which
data source it is behind.

**Both halves are used verbatim.** Bindings are indexed on the raw key and the
contract refuses case folding and Unicode normalisation, so nothing is
normalised here — a key matches what the operator registered character for
character, or it does not match at all. Dots inside a tool name stay ordinary
characters: an endpoint key is an opaque string to the control plane, and
inventing structure the other side does not parse would be a private dialect.

**No key is not a pass**, and the two keyless outcomes are not judged alike.
Admitting what could not be identified would let an unidentified caller
enumerate the tool surface with ``tools/list``, so both still face a chain —
but which chain is what the two are told apart for.

``keyless`` names no tool *by design*, so a rule keyed on the endpoint has no
subject to ask about and is dropped from the chain, while every other rule
applies as it would anywhere. ``unrecognised`` is a ``tools/call`` that **did**
name a tool, one this gateway declined to compose a key for, so nothing is
dropped and the whole chain applies — a rule about the endpoint holds against
it. `decide.chain_for` takes that as its ``keyless`` argument rather than
reading it off the absent key: both outcomes reach it as ``None``, and deciding
on the absence alone would let a caller shed every endpoint-derived rule by
appending a newline to a tool name.

**The two keyless outcomes are kept distinguishable on purpose.** They behave
identically for the caller, and an operator needs to tell them apart: drift and
garbage must never masquerade as *this endpoint simply has no rule*.

**There is deliberately no `batch` state**, and the TypeScript this is otherwise
ported from has one. It read raw JSON-RPC bodies off an Express request, where
an array body was a real shape to classify. Nothing of that survives here: this
runs above a parsed message, and MCP removed JSON-RPC batching in its 2025-06-18
revision — ``mcp.types`` carries no batch symbol at all. A state that cannot be
reached is worse than a missing one, because the comment explaining it teaches
the next reader to look for a hazard that no longer exists. Restore it only if
the protocol restores batching.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal

from gateway.key_safety import MAX_ENDPOINT_KEY_LENGTH, has_unsafe_key_characters

#: The MCP method that names a tool. Every other method is keyless.
CALL_METHOD = "tools/call"

#: How deeply a request body's JSON may nest before it reads as ``unrecognised``.
#:
#: **Ours, not the interpreter's**, for the reason `ticket.MAX_NESTING_DEPTH`
#: gives: `json.loads` recurses per nesting level and raises where the runtime
#: decides. Measured on the same body of brackets from a shallow stack, that is
#: depth 1000 on Python 3.10 and depth 10000 on 3.12 — and on 3.10 it moves down
#: with the caller's own stack depth, which inside an ASGI handler is deep. Left
#: to the runtime, the same body is read on one interpreter and raises out of
#: the layer on the other.
#:
#: **Deliberately not the sixty-four the header uses.** A ticket is a flat
#: object of scalars a mint issues; a body carries ``params.arguments``, which is
#: whatever JSON the tool this gateway fronts declares, composed by the caller
#: and nested as deep as that tool's own schema allows. Past this bound a body
#: is ``unrecognised``, and an ``unrecognised`` body faces the whole chain — so a
#: bound tight enough to catch a well-formed deep tool call would refuse real
#: traffic in order to enforce against it, which is a worse fault than the one
#: the bound is here for. Two hundred and fifty-six spends three levels on the
#: JSON-RPC frame and leaves the remaining two hundred and fifty-three to the
#: tool's argument tree, past anything a hand-written or generated schema nests,
#: while still clearing the 3.10 floor by a factor near four before the
#: handler's own stack is counted.
MAX_BODY_NESTING_DEPTH = 256

#: Read as byte values, because the body arrives as bytes and is scanned as bytes.
_QUOTE = ord('"')
_BACKSLASH = ord("\\")

#: Where a resolution can land.
#:
#: * ``resolved`` — a ``tools/call`` naming a usable tool, giving a qualified key.
#: * ``keyless`` — a method that names no tool by design: ``tools/list``,
#:   ``initialize``, ``resources/read`` and the rest.
#: * ``unrecognised`` — a ``tools/call`` whose tool name is missing, empty,
#:   unsafe to write into a log line, or long enough that no registered endpoint
#:   could match it. Evidence of drift or garbage, reported distinctly from
#:   "this endpoint has no rule".
ResolutionStatus = Literal["resolved", "keyless", "unrecognised"]


@dataclass(frozen=True)
class EndpointResolution:
    """A resolved key, or the absence of one and why."""

    key: str | None
    status: ResolutionStatus


def resolve_endpoint_key(
    method: Any, tool_name: Any, datasource_slug: str
) -> EndpointResolution:
    """Resolve one MCP message to an endpoint key.

    `method` and `tool_name` are taken off the parsed message rather than a
    body, because that is what a middleware is handed — by the time this runs,
    the transport has already refused anything that is not a well-formed
    message. Both are typed `Any` all the same: they cross a library boundary,
    and a resolver that trusts its caller's types is one that raises where a
    decision belongs.

    `datasource_slug` is ``RAIL_DATASOURCE_SLUG``, the data source this gateway
    fronts. Rail Center composes an endpoint's key from the same slug the data
    source was registered under, so both books are pinned to one value nobody
    re-types.
    """
    if method != CALL_METHOD:
        return EndpointResolution(None, "keyless")

    if not isinstance(tool_name, str) or not tool_name:
        # A `tools/call` naming no tool has no key to compose. Absence stays
        # absence: a half-composed key — the slug and a trailing dot — would
        # read downstream as a key that exists.
        return EndpointResolution(None, "unrecognised")
    if has_unsafe_key_characters(tool_name):
        # The tool name is chosen by the caller and the composed key is written
        # verbatim into a log line, and into a denial report once one is sent.
        return EndpointResolution(None, "unrecognised")

    key = f"{datasource_slug}.{tool_name}"
    if len(key) > MAX_ENDPOINT_KEY_LENGTH:
        # Past the control plane's cap the key can never match a registered
        # endpoint, and an unbounded tool name would otherwise ride into every
        # line the decision writes.
        return EndpointResolution(None, "unrecognised")

    return EndpointResolution(key, "resolved")


def _nesting_exceeds(body: bytes, limit: int) -> bool:
    """True when `body` nests brackets deeper than `limit`.

    Counted before parsing rather than caught during it, so the answer does not
    depend on which interpreter is running or on how deep the caller's stack
    already is. Quoted brackets do not count — a `"["` inside a tool argument is
    a character, and treating it as structure would refuse a legitimate call.

    Scanned as bytes, which is what the wire hands over: in UTF-8 no ASCII byte
    occurs inside a multi-byte character, so the bytes counted here are exactly
    the structural ones. A body in one of the UTF-16 or UTF-32 encodings
    `json.loads` also accepts can be miscounted, and the `RecursionError` caught
    at the parse is the floor under that.
    """
    depth = 0
    in_string = False
    escaped = False
    for char in body:
        if in_string:
            if escaped:
                escaped = False
            elif char == _BACKSLASH:
                escaped = True
            elif char == _QUOTE:
                in_string = False
            continue
        if char == _QUOTE:
            in_string = True
        elif char in b"[{":
            depth += 1
            if depth > limit:
                return True
        elif char in b"]}":
            depth -= 1
    return False


def resolve_from_body(body: bytes, datasource_slug: str) -> EndpointResolution:
    """Resolve a raw JSON-RPC request body to an endpoint key.

    The enforcement layer sits above the MCP server rather than inside it — a
    refusal there is an HTTP status, where inside it is a JSON-RPC error the
    denial contract does not describe — so it is handed bytes off the wire
    rather than a parsed message, and the parsing is its own.

    **A body this cannot read is `unrecognised`, never `keyless`.** The two
    behave alike for the caller and an operator has to tell them apart: a
    `tools/list` names no tool by design, while a body that is not an object is
    evidence of drift or garbage, and reporting the second as the first is how
    "this endpoint has no rule" comes to cover both.

    An array body lands there too. MCP removed JSON-RPC batching in its
    2025-06-18 revision, so nothing this gateway speaks to should send one — but
    the wire can still carry one, and a request naming no single tool has no key
    whatever the reason.

    A body nesting past `MAX_BODY_NESTING_DEPTH` lands there as well, and is
    refused on that count before it is parsed. **This never raises**, which is
    load-bearing: `_judge` calls it on its first line, above the `try` whose
    `except Exception` keeps a defect in the walk off the forward path, so an
    exception escaping here leaves the caller with neither a refusal nor a
    forward — and under `observe` the call is not forwarded at all, which is the
    one thing that mode exists to promise.
    """
    if _nesting_exceeds(body, MAX_BODY_NESTING_DEPTH):
        return EndpointResolution(None, "unrecognised")

    try:
        parsed = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return EndpointResolution(None, "unrecognised")
    except RecursionError:
        # A floor under the cap, not the answer to depth, and unreached while
        # the cap holds. The outcome is the same either way, so it costs nothing
        # and removes the one path by which this function could raise instead of
        # answering.
        return EndpointResolution(None, "unrecognised")
    if not isinstance(parsed, dict):
        return EndpointResolution(None, "unrecognised")

    method = parsed.get("method")
    if not isinstance(method, str) or not method:
        return EndpointResolution(None, "unrecognised")

    params = parsed.get("params")
    name = params.get("name") if isinstance(params, dict) else None
    return resolve_endpoint_key(method, name, datasource_slug)
