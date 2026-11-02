"""The `x-rail` ticket reader: decode a header and classify it.

The classification is rail-center's `docs/policy-evaluation-contract.md`, which
specifies what an enforcement point must implement so that both sides reach the
same verdict on the same ticket. The state names are its names deliberately — a
local vocabulary would be one more thing to translate when the two disagree.

A ticket comes in two forms. **Unsigned** is base64(JSON): anyone able to
construct JSON can forge one, so it is a compatibility format and not an
authentication credential. Reading it is still worth doing — an honest holder
is bounded by what it says, and the shape rules below close the cheapest
forgeries. **Signed** is a compact JWS — header, payload and Ed25519 signature —
checked against the tenant's keys in a `TicketVerifier`, and only a ticket that
verifies has its payload read at all. Which form a header is in is told by a
`.`, which no unsigned header can contain.

The signed reading is pinned by Rail Center's own vectors, copied into
`tests/vectors/signed_tickets.json`; the cases they cannot express are in
`tests/test_signed_ticket.py`.

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
   which the four levels of `posture.categories.<name>` does by a wide margin.
4. A leading byte-order mark is stripped here and kept there, so a ticket
   carrying one is `valid` here and `undecodable` in the reference. This is the
   one the reference is simply behind on — the contract names stripping as the
   rule and names `Buffer.toString("utf8")` as the reason most implementations
   need telling.
"""

import base64
import binascii
import json
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from gateway.core.json_wire import MAX_SAFE_INTEGER

#: How a ticket classified. **Only `valid` is usable**, and every claim of
#: anything else resolves to absent however readable the payload is.
#:
#: - ``absent``      no header, or an empty one
#: - ``undecodable`` the header arrived more than once; or is not decodable as
#:                   base64; or the bytes are not strictly valid UTF-8; or are
#:                   not JSON; or nest past ``MAX_NESTING_DEPTH``; or the value
#:                   handed over was not text at all; or, signed, not exactly
#:                   three non-empty parts, a part failing these rules, or a
#:                   header that is not a JSON object
#: - ``malformed``   not a JSON object; or an ``exp``
#:                   that is missing, fractional, non-numeric or outside
#:                   ±(2^53 − 1); or, signed, an ``nbf`` failing the same rules
#: - ``expired``     ``now >= exp``. A correctly-formed credential that is
#:                   simply too old — reported distinctly from ``undecodable``
#:                   for exactly that reason
#: - ``bad_signature`` signed, and the header claims another algorithm, names
#:                   no string ``kid`` or carries ``crit``; or no key set is
#:                   held, or none for its ``kid``; or the signature does not
#:                   verify. Also any unsigned ticket at a reader requiring
#:                   signatures
#: - ``wrong_audience`` signed and verified — Rail Center issued it — but not
#:                   for this reader: an ``iss`` or ``aud`` other than the ones
#:                   configured, none configured, or an ``nbf`` more than
#:                   ``NBF_ALLOWANCE_SEC`` ahead
#: - ``valid``       everything else
TicketState = Literal[
    "absent",
    "undecodable",
    "malformed",
    "bad_signature",
    "wrong_audience",
    "expired",
    "valid",
]

#: The one algorithm a signed ticket is issued and accepted with. Fixed by the
#: contract, and compared exactly: `eddsa` is not it.
JWS_ALG = "EdDSA"

#: How far ahead of this gateway's clock a signed ticket's `nbf` may be and
#: still be read, in seconds.
#:
#: **One-sided, unlike the `exp` comparison.** Rail Center stamps `nbf` with the
#: instant it serves the ticket and compensates for no one's clock, so a gateway
#: whose clock lags would refuse a fresh ticket for as long as it lags. `exp`
#: keeps `CLOCK_SKEW_TOLERANCE_SEC`, which is zero, so this never lengthens a
#: ticket's life; it only stops a new one being refused.
NBF_ALLOWANCE_SEC = 60

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
#: where the runtime decides: measured, that is depth 9997 on 3.12, and never in
#: the TypeScript reference, whose parser is iterative. Left to the runtime, the
#: same header would classify differently across implementations and versions.
#:
#: Sixty-four because the deepest a ticket nests is a category's score —
#: the ticket, `posture`, `categories`, the category: four levels used, and
#: sixty spare for a shape nobody has proposed. The contract asks only that the
#: limit sit above anything the mint can issue, which this clears by a factor
#: of sixteen.
MAX_NESTING_DEPTH = 64


@dataclass(frozen=True)
class ParseResult:
    """The classification, and the token only when it is usable."""

    state: TicketState
    #: Populated only when ``state`` is ``valid``. ``None`` otherwise, because
    #: the contract says every claim of an unusable ticket resolves to absent —
    #: returning a readable token would invite a caller to trust an expired
    #: ticket's ``posture.overall.score``.
    token: dict[str, Any] | None = None


@dataclass(frozen=True)
class TicketVerifier:
    """What a signed ticket is checked against: the key set held, and the
    issuer and audience of the tenant this gateway enforces for.

    `keys` maps each `kid` to its key, as `usable_keys` builds it from a
    fetched JWKS, and is None while no key set is held — never fetched, or past
    its maximum age. Fetching and ageing are the holder's I/O and clock, kept
    out of here so that a reading stays a function of the header, the time and
    these values.

    No verifier at all is a reader that holds no keys, is configured with no
    issuer or audience, and still accepts unsigned tickets: every reader before
    signing existed.
    """

    keys: Mapping[str, Ed25519PublicKey] | None = None
    issuer: str | None = None
    audience: str | None = None
    #: Read an unsigned ticket as `bad_signature`. Turned on once every agent
    #: this gateway fronts is served signed tickets, and not before: until then
    #: it refuses all of them.
    requires_signatures: bool = False


def usable_keys(jwks: Any) -> dict[str, Ed25519PublicKey] | None:
    """A fetched JWKS as the key set to hold, or None where the fetch counts as
    failed and replaces nothing.

    It counts only as an object whose `keys` hold at least one usable key —
    `kty` `OKP`, `crv` `Ed25519`, a string `kid` and an `x` decoding to exactly
    32 bytes — and in which no two entries share a `kid`. An entry that is not
    usable, or whose `use`, `key_ops` or `alg` says it is for something else,
    is skipped rather than refusing the set: a later Rail Center may publish
    entries for other purposes, and that must not stop verification.
    """
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        return None
    entries = jwks["keys"]
    # Counted over every entry, usable or not: two entries claiming one `kid`
    # leave no way to know which a ticket naming it meant.
    kids = [entry.get("kid") for entry in entries if isinstance(entry, dict)]
    if len(kids) != len({repr(kid) for kid in kids}):
        return None
    keys: dict[str, Ed25519PublicKey] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("kty") != "OKP" or entry.get("crv") != "Ed25519":
            continue
        kid, x = entry.get("kid"), entry.get("x")
        if not isinstance(kid, str) or not isinstance(x, str):
            continue
        if "use" in entry and entry["use"] != "sig":
            continue
        if "key_ops" in entry and not (
            isinstance(entry["key_ops"], list) and "verify" in entry["key_ops"]
        ):
            continue
        if "alg" in entry and entry["alg"] != JWS_ALG:
            continue
        raw = _decoded_part(x)
        if raw is None or len(raw) != 32:
            continue
        keys[kid] = Ed25519PublicKey.from_public_bytes(raw)
    return keys or None


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
    ticket carrying a score of `NaN` decodes here and does not there —
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

    An **absent** ``exp`` is malformed rather than unbounded. An unsigned
    ticket's keys can be deleted, and deleting one is strictly cheaper than
    corrupting it — reading a missing ``exp`` as "no expiry" would refuse the
    harder forgery and admit the easier one.

    ``bool`` is excluded explicitly because ``isinstance(True, int)`` is true in
    Python. Without saying so, this implementation would read ``exp: true`` as
    the year 1970 while the other refuses it.
    """
    return _usable_bound(claims.get("exp"))


def _usable_bound(value: Any) -> int | None:
    """A time claim — `exp`, or a signed ticket's `nbf` — as whole seconds,
    or None where it is not a whole number within ±(2^53 − 1)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float):
        # `is_integer` is false for both infinities and for NaN, so this covers
        # the non-finite cases without naming them.
        if not value.is_integer():
            return None
        value = int(value)
    if abs(value) > MAX_SAFE_INTEGER:
        return None
    return value


def parse_rail_header(
    value: str | list[str] | tuple[str, ...] | None,
    now: int | None = None,
    verifier: TicketVerifier | None = None,
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

    ``verifier`` is what a signed ticket is checked against. Without one, every
    well-formed signed ticket is ``bad_signature`` — no key set is held — and an
    unsigned one is read exactly as before.
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

    # `.` is outside both base64 alphabets, so no unsigned header carries one
    # and the test cannot misfire. It is also why a reader that predates
    # signing refuses a signed ticket as `undecodable` rather than admitting it.
    if "." in value:
        return _read_signed(value, now, verifier)

    # Before the payload is looked at: a reader still accepting both forms is
    # one where an attacker refused on a signed ticket answers with an
    # unsigned one, so signing protects nothing until this is on.
    if verifier is not None and verifier.requires_signatures:
        return ParseResult("bad_signature")

    raw = _decoded_part(value)
    if raw is None:
        return ParseResult("undecodable")
    parsed = _json_of(raw)
    if parsed is _UNDECODABLE:
        return ParseResult("undecodable")

    if not isinstance(parsed, dict):
        return ParseResult("malformed")

    # `exp` is the one claim read here, and the only one this gateway names at
    # all beside `id`: whether a ticket may be relied on is settled before any
    # policy runs, so it cannot be a policy's to describe. Every other claim is
    # whatever a policy's path asks for.
    # Shape before expiry, per the contract: a payload that is both shapeless
    # and stale reports `malformed`, so an operator is pointed at the fault that
    # has to be fixed first.
    exp = _usable_exp(parsed)
    if exp is None:
        return ParseResult("malformed")

    return _unexpired(parsed, exp, now)


def _unexpired(claims: dict[str, Any], exp: int, now: int) -> ParseResult:
    """`valid` carrying `claims`, unless `now` has reached `exp`."""
    # Added, not subtracted: a tolerance is grace past the stated expiry, so a
    # larger value widens the window. Subtracting would expire tickets early,
    # which is the opposite of what every reader of the constant expects.
    if now >= exp + CLOCK_SKEW_TOLERANCE_SEC:
        return ParseResult("expired")
    return ParseResult("valid", claims)


def _decoded_part(part: str) -> bytes | None:
    """One base64 part's bytes, or None where the contract calls it
    undecodable. The whole of an unsigned header is one part; a signed one has
    three, each held to the same rules."""
    # `=` comes off the end and nowhere else: a leading or interior one is a
    # corrupted body rather than a differently-padded one, and the alphabet
    # check below is what refuses it.
    body = part.rstrip("=")

    # The modulo is measured on the body rather than the raw header, which is
    # the half that bites: a header padded past what it needs measures 1 as a
    # whole while its body measures 2, and refusing it would turn away a ticket
    # that decodes. `binascii` refuses the other direction on its own, so the
    # rule earns its place here for stating what a reimplementation must do
    # rather than for what it changes on this runtime.
    if not _BASE64_BODY.fullmatch(body) or len(body) % 4 == 1:
        return None

    try:
        # Padding restored rather than required: a mint that strips it produces
        # a ticket the contract still calls decodable.
        padded = body + "=" * (-len(body) % 4)
        return base64.urlsafe_b64decode(padded.encode())
    except (binascii.Error, ValueError):
        return None


#: What `_json_of` returns for bytes that are not a ticket's JSON. A sentinel
#: rather than None, because `null` is JSON and parses to None.
_UNDECODABLE = object()


def _json_of(raw: bytes) -> Any:
    """`raw` read as a ticket's JSON, header or payload: strict UTF-8, one
    byte-order mark dropped, the nesting cap, no `NaN`, every number a double.
    `_UNDECODABLE` where any of that fails."""
    try:
        # `utf-8-sig` rather than `utf-8`: exactly one leading byte-order mark
        # is dropped, which is the rule the contract standardises on because
        # decoders split roughly evenly on it. A doubled mark leaves a U+FEFF
        # behind, and that is not JSON — which is the intended answer.
        decoded = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return _UNDECODABLE

    if _nesting_exceeds(decoded, MAX_NESTING_DEPTH):
        return _UNDECODABLE

    try:
        return json.loads(
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
        return _UNDECODABLE
    except RecursionError:
        # A floor under the cap, not the answer to depth, and unreached while
        # the cap holds. The state is the same either way, so it costs nothing
        # and removes the one path by which this function could raise instead of
        # answering.
        return _UNDECODABLE


def _read_signed(value: str, now: int, verifier: TicketVerifier | None) -> ParseResult:
    """A header containing `.`, read in the contract's order: structure,
    header, signature, payload, shape, then `nbf`/`iss`/`aud`, then expiry."""
    parts = value.split(".")
    if len(parts) != 3 or not all(parts):
        return ParseResult("undecodable")
    decoded = [_decoded_part(part) for part in parts]
    if any(part is None for part in decoded):
        return ParseResult("undecodable")
    header_bytes, payload_bytes, signature = decoded
    header = _json_of(header_bytes)
    if header is _UNDECODABLE or not isinstance(header, dict):
        return ParseResult("undecodable")

    # **Nothing in the header chooses how the ticket is verified.** `alg` is
    # checked only to refuse a ticket claiming another algorithm, and Ed25519
    # is used whatever it says: a reader that dispatches on `alg` is the one
    # that accepts `none`. Every other member — `typ`, and `jku`, `x5u` and
    # `jwk`, which would name a key — is ignored; keys come only from the set
    # this gateway fetched.
    kid = header.get("kid")
    if header.get("alg") != JWS_ALG or not isinstance(kid, str) or "crit" in header:
        return ParseResult("bad_signature")
    if verifier is None or verifier.keys is None:
        return ParseResult("bad_signature")
    key = verifier.keys.get(kid)
    if key is None:
        return ParseResult("bad_signature")
    try:
        # Over the two parts exactly as they arrived, not re-encoded: the
        # decoder above accepts spellings the signer did not use, and the
        # signature is over what was sent. ASCII is safe: the alphabet check
        # has already held both parts to it.
        key.verify(signature, f"{parts[0]}.{parts[1]}".encode("ascii"))
    except InvalidSignature:
        return ParseResult("bad_signature")

    # Only now is the payload read, so nothing in a forged one — its `id`
    # included — reaches a rule or a denial report.
    claims = _json_of(payload_bytes)
    if claims is _UNDECODABLE:
        return ParseResult("undecodable")
    if not isinstance(claims, dict):
        return ParseResult("malformed")
    exp = _usable_exp(claims)
    nbf = _usable_bound(claims.get("nbf"))
    if exp is None or nbf is None:
        return ParseResult("malformed")

    # **Genuine, so `bad_signature` would misreport it; not for this reader, so
    # not usable either.** A reader with nothing to compare against accepts
    # nothing rather than skipping the check: a skipped `aud` check is how one
    # tenant's ticket is admitted at another's gateway.
    if verifier.issuer is None or verifier.audience is None:
        return ParseResult("wrong_audience")
    if now < nbf - NBF_ALLOWANCE_SEC:
        return ParseResult("wrong_audience")
    if claims.get("iss") != verifier.issuer:
        return ParseResult("wrong_audience")
    audience = claims.get("aud")
    # A string, exactly: RFC 7519 allows a list, and membership in one is a
    # second rule to implement that nothing Rail Center issues needs.
    if not isinstance(audience, str) or audience != verifier.audience:
        return ParseResult("wrong_audience")

    return _unexpired(claims, exp, now)
