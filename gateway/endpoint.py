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

**No key is not a pass.** Both keyless outcomes are judged by the entire policy
chain, because the alternative — admitting what could not be identified — would
let an unidentified caller enumerate the tool surface with ``tools/list``. The
rules that key on ``endpoint_key`` decline to hold against an absence, and every
other rule applies as it would anywhere.

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

from dataclasses import dataclass
from typing import Any, Literal

from gateway.key_safety import MAX_ENDPOINT_KEY_LENGTH, has_unsafe_key_characters

#: The MCP method that names a tool. Every other method is keyless.
CALL_METHOD = "tools/call"

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
