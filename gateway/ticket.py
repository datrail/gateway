"""The `x-rail` ticket reader: decode a header and classify it.

The classification is rail-center's `docs/policy-evaluation-contract.md`, which
specifies what an enforcement point must implement so that both sides reach the
same verdict on the same ticket. The state names are its names deliberately — a
local vocabulary would be one more thing to translate when the two disagree.

Wave 1 tickets are unsigned base64(JSON): anyone able to construct JSON can
forge one, so this is a compatibility format and not an authentication
credential. Reading it is still worth doing — an honest holder is bounded by
what it says, and the shape rules below close the cheapest forgeries.

**Four known divergences from the TypeScript implementation, each decided in
favour of the contract and each carried in the vectors.** Two are about bytes
that cannot be read, one is a limit this file sets and the reference does not,
and one is a rule the reference has not caught up with.

1. Invalid UTF-8 *inside a JSON string* is `undecodable` here and `valid` there:
   `Buffer.toString` substitutes U+FFFD and never throws, so the reference
   admits an `agent_id` with a replacement character in it.
2. Invalid UTF-8 in a *key* is `undecodable` here and `malformed` there, for the
   same reason — the substituted key is not `agent_id`, so the reference gets
   as far as looking for one and not finding it. Both refuse, and they disagree
   on which state — which matters to whatever eventually reports the refusal,
   not to whether the request is admitted.
3. Nesting past `MAX_NESTING_DEPTH` is `undecodable` here and parses there. The
   contract expects this one and bounds it: implementations' limits differ, so
   what it requires is that the limit sit above anything the mint can issue,
   which two levels of `skills` does by a wide margin.
4. A leading byte-order mark is stripped here and kept there, so a ticket
   carrying one is `valid` here and `undecodable` in the reference. This is the
   one the reference is simply behind on — the contract names stripping as the
   rule and names `Buffer.toString("utf8")` as the reason most implementations
   need telling.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Literal

from gateway.json_wire import MAX_SAFE_INTEGER

#: How a ticket classified. **Only `valid` is usable**, and every claim of
#: anything else resolves to absent however readable the payload is.
#:
#: - ``absent``      no header, or an empty one
#: - ``undecodable`` the header arrived more than once; or is not decodable as
#:                   base64; or the bytes are not strictly valid UTF-8; or are
#:                   not JSON; or nest past ``MAX_NESTING_DEPTH``; or the value
#:                   handed over was not text at all
#: - ``malformed``   not a JSON object; no string ``agent_id``; or an ``exp``
#:                   that is missing, fractional, non-numeric or outside
#:                   ±(2^53 − 1)
#: - ``expired``     ``now >= exp``. A correctly-formed credential that is
#:                   simply too old — reported distinctly from ``undecodable``
#:                   for exactly that reason
#: - ``valid``       everything else
TicketState = Literal["absent", "undecodable", "malformed", "expired", "valid"]

#: Clock-skew tolerance, in seconds, applied when comparing ``now`` to ``exp``.
#:
#: **Zero, by decision.** RFC 7519 permits a small leeway and API gateways
#: commonly default to 30–60s, but this deployment should not:
#:
#:   * The evaluation contract states the comparison as ``now >= exp`` with no
#:     leeway, and its conformance cases pin exact boundaries against a fixed
#:     ``now``. Any tolerance here makes the gateway and the control plane
#:     answer differently on a boundary ticket — the divergence that contract
#:     exists to remove.
#:   * Skew does not bite in practice. The mint's TTL is 900s and the proxy
#:     refreshes at half the remaining life, so a presented ticket normally has
#:     hundreds of seconds in hand. A clock far enough out to matter is a broken
#:     host, and widening the window would hide it rather than fix it.
#:   * The window is also how long a downgraded agent keeps being admitted.
#:     Tolerance spends that budget for no gain.
#:
#: Named and exported so the value is a choice a reader can find, not an absence
#: they have to infer.
CLOCK_SKEW_TOLERANCE_SEC = 0

#: The base64 alphabet, standard and URL-safe both. Enforced rather than left to
#: the decoder, which discards anything outside it — `binascii` and Node's
#: `Buffer.from` alike. Two spellings turn on that: a MIME-wrapped header, the
#: newline every 64 or 76 characters `openssl base64` and Java's MIME encoder
#: emit, decodes cleanly to a whole and fully-honoured ticket; and a pair of
#: padded tickets run together decodes to the first alone, because both decoders
#: stop at its padding — so whoever concatenates them picks which one is read.
#: Neither is refused by anything else here, which is why the contract asks for
#: the check.
#:
#: `=` is deliberately outside the class. It is stripped from the end before the
#: match, so one surviving anywhere else is a corrupted body — which is what the
#: second spelling above is, and what nothing else here would refuse.
_BASE64_BODY = re.compile(r"[A-Za-z0-9\-_+/]*")

#: How deeply a ticket's JSON may nest before it is refused as `undecodable`.
#:
#: **Ours, not the interpreter's.** `json.loads` recurses per level and raises
#: where the runtime decides: measured, that is depth 994 on Python 3.10, 9997
#: on 3.12, and never in the TypeScript reference, whose parser is iterative. On
#: 3.10 it also moves with the caller's own stack depth, so the same header
#: classified two ways depending on where it was read from. A gateway parses
#: headers from inside a request handler, which is a deep stack.
#:
#: Sixty-four because a ticket is a flat object of scalars with one array of
#: skills — two levels used, and sixty-two spare for a shape nobody has
#: proposed. The contract asks only that the limit sit above anything the mint
#: can issue, which this clears by a factor of thirty.
MAX_NESTING_DEPTH = 64


@dataclass(frozen=True)
class ParseResult:
    """The classification, and the token only when it is usable."""

    state: TicketState
    #: Populated only when ``state`` is ``valid``. ``None`` otherwise, because
    #: the contract says every claim of an unusable ticket resolves to absent —
    #: returning a readable token would invite a caller to trust an expired
    #: ticket's ``posture_score``.
    token: dict[str, Any] | None = None


def _nesting_exceeds(text: str, limit: int) -> bool:
    """True when `text` nests brackets deeper than `limit`.

    Counted before parsing rather than caught during it, so the answer does not
    depend on which interpreter is running or how deep the caller's stack
    already is. Quoted brackets do not count — a `"["` inside a string is a
    character, and treating it as structure would refuse a legitimate skill
    name.
    """
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > limit:
                return True
        elif char in "]}":
            depth -= 1
    return False


def _reject_non_json_constant(name: str) -> Any:
    """Refuse `NaN`, `Infinity` and `-Infinity`.

    Python's `json` accepts all three by default; they are not JSON, and the
    reference implementation's `JSON.parse` rejects them. Left accepted, a
    ticket carrying `"posture_score": NaN` decodes here and does not there —
    and a NaN satisfies neither `score < 40` nor `score >= 40`, so it passes a
    threshold rule from both directions while every type check calls it a
    number.
    """
    raise ValueError(f"{name} is not JSON")


def _now_seconds() -> int:
    """Whole seconds since the Unix epoch, UTC — the units ``exp`` is in."""
    return int(time.time())


def _usable_exp(claims: dict[str, Any]) -> int | None:
    """The ``exp`` claim if it is one this contract can compare, else ``None``.

    An **absent** ``exp`` is malformed rather than unbounded. The token is
    unsigned, so deleting a key is strictly cheaper than corrupting one —
    reading a missing ``exp`` as "no expiry" would refuse the harder forgery and
    admit the easier one.

    ``bool`` is excluded explicitly because ``isinstance(True, int)`` is true in
    Python. Without saying so, this implementation would read ``exp: true`` as
    the year 1970 while the other refuses it.
    """
    exp = claims.get("exp")
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        return None
    if isinstance(exp, float):
        # `is_integer` is false for both infinities and for NaN, so this covers
        # the non-finite cases without naming them.
        if not exp.is_integer():
            return None
        exp = int(exp)
    if abs(exp) > MAX_SAFE_INTEGER:
        return None
    return exp


def parse_rail_header(
    value: str | list[str] | tuple[str, ...] | None, now: int | None = None
) -> ParseResult:
    """Decode and classify an ``x-rail`` header value.

    ``value`` takes the *whole* header — a list or tuple where the framework can
    report repeats, as Starlette's ``Headers.getlist`` does, and a plain string
    where it cannot. The contract refuses a repeated header outright, and it has
    to be refused here rather than downstream: by the time a platform has
    collapsed two values into one the evidence is gone, and the two platforms
    collapse them differently — Node joins them, Starlette keeps the first — so
    a caller choosing which line to add chooses which side reads a usable
    ticket.

    Anything that is neither of those — the raw ``bytes`` a bare ASGI scope
    carries, say — is ``undecodable`` rather than an exception. A reader sitting
    on the deny path must answer with a state whatever it is handed; raising
    here would leave the caller's error handler to decide the request, which is
    neither an allow nor a deny.

    ``now`` is injectable so expiry is testable without waiting and without a
    restart, and so a caller can judge a whole request against one instant.
    """
    if now is None:
        now = _now_seconds()

    if isinstance(value, (list, tuple)):
        if len(value) > 1:
            return ParseResult("undecodable")
        value = value[0] if value else None

    if value is None:
        return ParseResult("absent")

    # Before the emptiness test, not after. Emptiness runs the object's own
    # `__eq__` and `__bool__`, and an array-like returns an array from the first
    # and raises from the second. The point of answering rather than raising is
    # lost if the check deciding whether to answer runs the caller's code.
    if not isinstance(value, str):
        return ParseResult("undecodable")

    if not value:
        return ParseResult("absent")

    # `=` comes off the end and nowhere else: a leading or interior one is a
    # corrupted body rather than a differently-padded one, and the alphabet
    # check below is what refuses it.
    body = value.rstrip("=")

    # The modulo is measured on the body rather than the raw header, which is
    # the half that bites: a header padded past what it needs measures 1 as a
    # whole while its body measures 2, and refusing it would turn away a ticket
    # that decodes. `binascii` refuses the other direction on its own, so the
    # rule earns its place here for stating what a reimplementation must do
    # rather than for what it changes on this runtime.
    if not _BASE64_BODY.fullmatch(body) or len(body) % 4 == 1:
        return ParseResult("undecodable")

    try:
        # Padding restored rather than required: a mint that strips it produces
        # a ticket the contract still calls decodable.
        padded = body + "=" * (-len(body) % 4)
        # `utf-8-sig` rather than `utf-8`: exactly one leading byte-order mark
        # is dropped, which is the rule the contract standardises on because
        # decoders split roughly evenly on it. A doubled mark leaves a U+FEFF
        # behind, and that is not JSON — which is the intended answer.
        decoded = base64.urlsafe_b64decode(padded.encode()).decode("utf-8-sig")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return ParseResult("undecodable")

    if _nesting_exceeds(decoded, MAX_NESTING_DEPTH):
        return ParseResult("undecodable")

    try:
        parsed = json.loads(
            decoded,
            parse_constant=_reject_non_json_constant,
            # Every number is a double, on both sides of every comparison.
            # Python's ints are arbitrary-precision, so left alone this file
            # would hold values `JSON.parse` cannot tell apart — 2^53 and
            # 2^53 + 1 are one double and two ints — and a threshold rule would
            # answer differently on the two sides. Narrowing here also puts
            # CPython's 4300-digit conversion limit out of the way: the digits
            # never become an int, so a long literal saturates to infinity
            # exactly as it does in the reference instead of raising.
            parse_int=float,
        )
    except (ValueError, TypeError):
        return ParseResult("undecodable")
    except RecursionError:
        # A floor under the cap, not the answer to depth, and unreached while
        # the cap holds. The state is the same either way, so it costs nothing
        # and removes the one path by which this function could raise instead of
        # answering.
        return ParseResult("undecodable")

    if not isinstance(parsed, dict):
        return ParseResult("malformed")

    if not isinstance(parsed.get("agent_id"), str):
        return ParseResult("malformed")

    # Shape before expiry, per the contract: a payload that is both shapeless
    # and stale reports `malformed`, so an operator is pointed at the fault that
    # has to be fixed first.
    exp = _usable_exp(parsed)
    if exp is None:
        return ParseResult("malformed")

    # Added, not subtracted: a tolerance is grace past the stated expiry, so a
    # larger value widens the window. Subtracting would expire tickets early,
    # which is the opposite of what every reader of the constant expects.
    if now >= exp + CLOCK_SKEW_TOLERANCE_SEC:
        return ParseResult("expired")

    return ParseResult("valid", parsed)
