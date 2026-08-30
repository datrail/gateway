"""Which MCP messages resolve to an endpoint key, and which do not.

`gateway/endpoint.py` is this gateway's own composition and appears nowhere in
rail-center's `docs/policy-evaluation-contract.md`: the contract hands an
evaluator a key that has already been resolved, and says so under *What the
vectors cannot reach*. No vector file covers any of this, which is why these
are ordinary unit tests rather than cases in `tests/vectors/`.

What they pin is the three-way split. A `resolved` key is judged by the rules
bound to it; both keyless outcomes are judged by the whole chain and behave
identically for the caller. That last part is why the split is easy to erode —
nothing a caller sees changes when `unrecognised` collapses into `keyless` —
and it is exactly what an operator needs, because drift and garbage must never
masquerade as *this endpoint simply has no rule*.
"""

from __future__ import annotations

import pytest

from gateway.endpoint import resolve_endpoint_key
from gateway.key_safety import MAX_ENDPOINT_KEY_LENGTH

SLUG = "delivery"


def resolve(method: object = "tools/call", tool_name: object = "track_package"):
    """The resolution as a pair, so a case reads as key-and-status."""
    resolution = resolve_endpoint_key(method, tool_name, SLUG)
    return resolution.key, resolution.status


# --- a call that names a usable tool --------------------------------------


def test_the_key_is_the_slug_and_the_tool_name_verbatim():
    """Both halves unnormalised. Bindings are indexed on the raw key and the
    contract refuses case folding and Unicode normalisation, so a key matches
    what the operator registered character for character or not at all."""
    assert resolve(tool_name="Track_Package") == ("delivery.Track_Package", "resolved")


def test_dots_inside_a_tool_name_stay_ordinary_characters():
    """An endpoint key is an opaque string to the control plane. Inventing
    structure the other side does not parse would be a private dialect."""
    assert resolve(tool_name="orders.v2") == ("delivery.orders.v2", "resolved")


# --- a message that names no tool by design -------------------------------


@pytest.mark.parametrize(
    "method",
    [
        "initialize",
        "notifications/initialized",
        "tools/list",
        "resources/read",
        "",
        None,
    ],
)
def test_every_method_but_tools_call_is_keyless(method):
    """`tools/call` is the only method that names a tool. Everything else has
    no key to compose and is not evidence of anything being wrong."""
    assert resolve(method=method) == (None, "keyless")


# --- a call that names something unusable ---------------------------------


@pytest.mark.parametrize(
    "tool_name", [None, "", 17, [], {}, b"track_package", True, 3.5]
)
def test_a_tools_call_naming_no_usable_tool_is_unrecognised_not_keyless(tool_name):
    """**The distinction the module keeps on purpose.** A `tools/call` with no
    readable tool name is drift or garbage, and reporting it as `keyless` —
    which the caller-visible behaviour would let you get away with, since the
    two are judged identically — files it under *this endpoint has no rule*,
    where nobody goes looking.

    A half-composed key is the other wrong answer: the slug and a trailing dot
    would read downstream as a key that exists.
    """
    assert resolve(tool_name=tool_name) == (None, "unrecognised")


@pytest.mark.parametrize(
    ("why", "tool_name"),
    [
        ("a null byte", "track\x00package"),
        ("a newline, which forges a second log line", "track\npackage"),
        ("a carriage return", "track\rpackage"),
        ("an escape, which starts a terminal sequence", "track\x1bpackage"),
        ("a right-to-left override", "track\u202epackage"),
        ("a zero-width joiner", "track\u200dpackage"),
        ("a line separator", "track\u2028package"),
        ("a paragraph separator", "track\u2029package"),
        ("an unpaired surrogate", "track\ud800package"),
    ],
)
def test_a_tool_name_unsafe_to_log_is_unrecognised(why, tool_name):
    """The tool name is chosen by the caller and the composed key is written
    verbatim into every line the decision writes, and into a denial report once
    one is sent. Without this guard a control character or a bidi override
    rides into all of them."""
    assert resolve(tool_name=tool_name) == (None, "unrecognised"), why


def test_a_key_past_the_control_plane_cap_is_unrecognised():
    """Past the cap the key can never match a registered endpoint, and an
    unbounded tool name would otherwise ride into every line the decision
    writes. Asserted from both sides of the bound, so a guard that is merely
    off by one is not mistaken for one that is there."""
    fits = "t" * (MAX_ENDPOINT_KEY_LENGTH - len(SLUG) - 1)
    assert len(f"{SLUG}.{fits}") == MAX_ENDPOINT_KEY_LENGTH
    assert resolve(tool_name=fits) == (f"{SLUG}.{fits}", "resolved")

    assert resolve(tool_name=fits + "t") == (None, "unrecognised")


def test_the_bound_is_on_the_composed_key_rather_than_the_tool_name():
    """A tool name that would fit under the cap on its own still composes a key
    past it, and the key is what has to match a registered endpoint."""
    tool_name = "t" * MAX_ENDPOINT_KEY_LENGTH
    assert resolve(tool_name=tool_name) == (None, "unrecognised")
