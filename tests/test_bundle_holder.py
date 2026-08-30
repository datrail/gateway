"""Holding the policy bundle, and every way of failing to.

The rule under test is one sentence of the evaluation contract:

> An enforcement point that cannot reach `GET /v1/policy-bundle` has no ruleset,
> which is not the same as an empty one. It must keep serving the last bundle it
> holds, and refuse traffic if it has never held one.

An empty chain **allows**, so every case below asks the same question in a
different way: after this failure, is what is held still what was held — and
when nothing was ever held, is it still nothing? A test that only checked the
outcome's `kind` would pass on an implementation that cleared the bundle and
reported the failure honestly, which is the bug this file exists to catch.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import logging
import random
import struct
import tracemalloc
import zlib
from typing import Any

import httpx
import pytest

from gateway.bundle import client as bundle_client
from gateway.bundle.client import (
    BUNDLE_PATH,
    DEFAULT_REFRESH_SECONDS,
    FETCH_DEADLINE_SECONDS,
    MIN_REFRESH_SECONDS,
    BundleHolder,
    refresh_seconds,
)

ONE = "5c8f1e42-0000-4000-8000-0000000000a1"
TWO = "5c8f1e42-0000-4000-8000-0000000000a2"


def bundle(version: str = "v1", *, policies: Any = None, rejected: Any = None) -> dict:
    return {
        "version": version,
        "policies": [{"id": ONE, "name": "P", "priority": 1}]
        if policies is None
        else policies,
        "bindings": [],
        "rejected": [] if rejected is None else rejected,
    }


def responder(*responses: httpx.Response | Exception):
    """A control plane that answers each request with the next thing given.

    Exhausting it is a test bug rather than a scenario, so it raises rather
    than repeating the last answer — a holder that fetched more often than the
    test expected would otherwise pass quietly.
    """
    remaining = list(responses)

    def handle(_request: httpx.Request) -> httpx.Response:
        if not remaining:
            raise AssertionError("the holder fetched more times than the test supplied")
        answer = remaining.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    return httpx.MockTransport(handle)


def streamed(
    body: bytes, encoding: str | None = None, *, chunk_bytes: int = 16 * 1024
) -> httpx.Response:
    """A response httpx has not already read, which is what a socket hands over.

    A `Response` built from bytes is read at construction and `read()` applies
    `Content-Encoding`, so an encoded body built that way reaches the holder
    already decoded — a shape no deployment has. Arriving in chunks, it reaches
    the holder as it left the responder.

    `chunk_bytes` is how a socket's own framing is chosen: a bound the holder
    reaches part-way through a body needs chunks smaller than the bound, or the
    first one carries the whole overrun and nothing accumulates.
    """

    async def chunks():
        for start in range(0, len(body), chunk_bytes):
            yield body[start : start + chunk_bytes]

    return httpx.Response(
        200,
        content=chunks(),
        headers={"content-encoding": encoding} if encoding else {},
    )


def holder(*responses: httpx.Response | Exception, **kwargs: Any) -> BundleHolder:
    return BundleHolder(
        "http://rail-center.test", {}, transport=responder(*responses), **kwargs
    )


# --- what is held, and what happens to it ---------------------------------


@pytest.mark.asyncio
async def test_a_first_fetch_is_held() -> None:
    h = holder(httpx.Response(200, json=bundle("v1")))
    outcome = await h.refresh()

    assert outcome.kind == "replaced"
    assert h.current() is not None
    assert h.current().version == "v1"
    assert [p.id for p in h.current().chain] == [ONE]


@pytest.mark.asyncio
async def test_nothing_is_held_before_the_first_fetch() -> None:
    """`None` means refuse, and it is the state a gateway starts in."""
    assert holder().current() is None


@pytest.mark.parametrize(
    ("label", "answer"),
    [
        ("a 503", httpx.Response(503)),
        ("a 500", httpx.Response(500)),
        ("a 404", httpx.Response(404)),
        ("a refused credential", httpx.Response(401)),
        ("a forbidden read", httpx.Response(403)),
        ("a connection failure", httpx.ConnectError("connection refused")),
        ("a timeout", httpx.ReadTimeout("timed out")),
        ("a body that is not JSON", httpx.Response(200, content=b"<html>nope</html>")),
        ("an empty body", httpx.Response(200, content=b"")),
    ],
)
@pytest.mark.asyncio
async def test_a_failed_fetch_keeps_the_bundle_already_held(
    label: str, answer: httpx.Response | Exception
) -> None:
    """The rule, from the side that matters most.

    Nine ways of not getting a bundle, and after every one the gateway is still
    enforcing the ruleset it had. An implementation that cleared the held bundle
    would report the failure just as honestly and admit every request.
    """
    h = holder(httpx.Response(200, json=bundle("v1")), answer)
    await h.refresh()

    outcome = await h.refresh()

    assert outcome.kind == "unreachable", label
    assert outcome.held == "v1", label
    assert h.current().version == "v1", label


@pytest.mark.parametrize(
    ("label", "answer"),
    [
        ("a 503", httpx.Response(503)),
        ("a refused credential", httpx.Response(401)),
        ("a connection failure", httpx.ConnectError("connection refused")),
        ("a body that is not JSON", httpx.Response(200, content=b"<html>nope</html>")),
    ],
)
@pytest.mark.asyncio
async def test_a_failed_first_fetch_holds_nothing(
    label: str, answer: httpx.Response | Exception
) -> None:
    """The other side of the same rule: nothing held means refuse.

    Not an empty bundle, which would allow — `current()` is None, and the
    caller's job is to turn that into a refusal.
    """
    h = holder(answer)
    outcome = await h.refresh()

    assert outcome.kind == "unreachable", label
    assert outcome.held is None, label
    assert h.current() is None, label


@pytest.mark.asyncio
async def test_a_bundle_that_cannot_be_applied_keeps_the_one_held() -> None:
    """Distinct from unreachable, and for a reason an operator acts on.

    `unusable` means Rail Center and this gateway have drifted, and the offending
    policy is named; `unreachable` means the network or the credential. Both keep
    what is held, and telling them apart is what decides who to page.
    """
    h = holder(
        httpx.Response(200, json=bundle("v1")),
        httpx.Response(200, json=bundle("v2", policies="not a list")),
    )
    await h.refresh()

    outcome = await h.refresh()

    assert outcome.kind == "unusable"
    assert outcome.held == "v1"
    assert h.current().version == "v1"
    assert "`policies` is not a list" in outcome.reason


@pytest.mark.asyncio
async def test_an_unusable_first_bundle_holds_nothing() -> None:
    h = holder(httpx.Response(200, json=bundle("v1", policies="not a list")))
    outcome = await h.refresh()

    assert outcome.kind == "unusable"
    assert h.current() is None


@pytest.mark.asyncio
async def test_an_unusable_first_bundle_claims_no_refusal_in_the_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The twin of the unreachable line, and the one the suite never reached.

    An unreachable control plane is driven by the readiness suite, which
    asserts nothing there claims a refusal; nothing drove the *unusable* path,
    where the second of these two lines lives. What is true of both is that
    the gateway holding no bundle forwards the request anyway — so an operator
    reading a claim of refused traffic hunts refusals that never happened
    while every call goes through unjudged. The bundle is refused; traffic is
    not, and only one of those two words may appear.
    """
    h = holder(httpx.Response(200, json=bundle("v1", policies="not a list")))
    with caplog.at_level(logging.WARNING, logger="gateway.bundle"):
        await h.refresh()

    said = "\n".join(r.getMessage() for r in caplog.records)
    assert "no bundle held, so nothing is enforced" in said, said
    assert "refusing traffic" not in said, said


@pytest.mark.asyncio
async def test_a_new_version_replaces_what_is_held() -> None:
    h = holder(
        httpx.Response(200, json=bundle("v1")),
        httpx.Response(
            200, json=bundle("v2", policies=[{"id": TWO, "name": "Q", "priority": 9}])
        ),
    )
    await h.refresh()

    outcome = await h.refresh()

    assert outcome.kind == "replaced"
    assert h.current().version == "v2"
    assert [p.id for p in h.current().chain] == [TWO]


# --- the version short-circuit --------------------------------------------


@pytest.mark.asyncio
async def test_an_unchanged_version_is_not_reparsed() -> None:
    """Proven by sending a body that validation would refuse.

    `version` is a content hash, so an unchanged one means what is held is
    byte-for-byte what arrived and there is nothing to re-parse. The only way to
    show the short-circuit really happens is to make the un-taken path fail: the
    second answer carries the held version and a `policies` that is not a list.
    An implementation that validated first would report `unusable`.
    """
    h = holder(
        httpx.Response(200, json=bundle("v1")),
        httpx.Response(200, json=bundle("v1", policies="not a list")),
    )
    await h.refresh()

    outcome = await h.refresh()

    assert outcome.kind == "unchanged"
    assert h.current().version == "v1"


@pytest.mark.asyncio
async def test_the_short_circuit_needs_a_bundle_to_be_held() -> None:
    """A first response is validated however its version reads.

    Comparing against a held version of None would match a bundle whose version
    key is missing, and a bundle nothing validated must never be held.
    """
    h = holder(
        httpx.Response(200, json={"policies": [], "bindings": [], "rejected": []})
    )
    outcome = await h.refresh()

    assert outcome.kind == "unusable"
    assert h.current() is None


# --- what the fetch bounds ------------------------------------------------


@pytest.mark.asyncio
async def test_a_body_past_the_bound_is_refused_even_when_it_lies_about_its_length() -> (
    None
):
    """The declared length is the server's claim; the body is the fact.

    A responder that under-declares walks past the header check, so the body has
    to be measured too — and it is the only check left once the header is gone.
    """
    h = holder(
        httpx.Response(
            200,
            content=b'{"version":"v2","policies":[],"bindings":[],"rejected":[]}'
            + b" " * 4000,
            headers={"content-length": "10"},
        ),
        max_bytes=1024,
    )
    outcome = await h.refresh()

    assert outcome.kind == "unreachable"
    assert "past the 1024" in outcome.reason
    assert h.current() is None


@pytest.mark.asyncio
async def test_a_4xx_carrying_a_perfectly_good_bundle_is_still_refused() -> None:
    """The status decides, not the body.

    A control plane answering 404 with a bundle-shaped body is one that has been
    reconfigured, or one this gateway is pointed at by mistake. Reading the body
    anyway would hold a ruleset from a route that does not exist.
    """
    h = holder(
        httpx.Response(200, json=bundle("v1")),
        httpx.Response(404, json=bundle("v2")),
    )
    await h.refresh()

    outcome = await h.refresh()

    assert outcome.kind == "unreachable"
    assert "responded 404" in outcome.reason
    assert h.current().version == "v1"


@pytest.mark.asyncio
async def test_a_body_past_the_bound_is_treated_as_unreachable() -> None:
    """Refused, and the bundle held stays in force.

    The deadline bounds how long a response may take and says nothing about how
    large it may be, so a control plane answering quickly with an enormous body
    would otherwise be buffered whole before anything looked at it.
    """
    huge = bundle("v2", policies=[{"id": ONE, "name": "x" * 5000, "priority": 1}])
    h = holder(
        httpx.Response(200, json=bundle("v1")),
        httpx.Response(200, json=huge),
        max_bytes=1024,
    )
    await h.refresh()

    outcome = await h.refresh()

    assert outcome.kind == "unreachable"
    assert "past the 1024" in outcome.reason
    assert h.current().version == "v1"


@pytest.mark.asyncio
async def test_a_wire_body_past_the_bound_is_refused_across_chunks() -> None:
    """The bound on the wire is the only one a body like this ever meets.

    Every other test of it hands the body over whole, which reaches the holder
    as a single chunk — so the running total never runs, and a bound that only
    ever saw the last chunk would look identical from outside. This body is
    half a megabyte of empty gzip blocks around sixty-five bytes of perfectly
    good bundle: what it decodes to is far inside the bound, so the decode
    guard never fires and nothing but the wire total can stop the read. A real
    socket delivers every body in more than one chunk, which is what makes this
    the ordinary case rather than the exotic one.
    """
    payload = json.dumps(bundle("v2")).encode()
    # Deflate stored blocks: five bytes of framing each, none of them carrying
    # a byte of output, then a final one holding the whole bundle.
    empty = b"\x00" + struct.pack("<HH", 0, 0xFFFF)
    carrying = b"\x01" + struct.pack("<HH", len(payload), len(payload) ^ 0xFFFF)
    body = (
        b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03"
        + empty * 100_000
        + carrying
        + payload
        + struct.pack("<II", zlib.crc32(payload), len(payload))
    )
    limit = 4096

    assert len(body) > limit, "the wire size is the whole point"
    assert len(payload) < limit, "and what it decodes to must be well inside it"

    h = holder(
        httpx.Response(200, json=bundle("v1")),
        streamed(body, "gzip", chunk_bytes=512),
        max_bytes=limit,
    )
    await h.refresh()

    outcome = await h.refresh()

    assert outcome.kind == "unreachable"
    assert f"is past the {limit}" in outcome.reason
    assert h.current().version == "v1"


@pytest.mark.asyncio
async def test_a_declared_length_past_the_bound_is_refused_before_the_body() -> None:
    """The header is read first, so a body past the bound is never read at all.

    The running total below covers a responder that under-declares; this covers
    the honest one, and costs it nothing.
    """
    h = holder(
        httpx.Response(200, json=bundle("v1"), headers={"content-length": "999999"}),
        max_bytes=1024,
    )
    outcome = await h.refresh()

    assert outcome.kind == "unreachable"
    assert "declares 999999 bytes" in outcome.reason
    assert h.current() is None


@pytest.mark.asyncio
async def test_a_bundle_of_exactly_the_bound_is_read() -> None:
    """The bound is the largest bundle read, not the smallest one refused.

    Both halves of the check carry the same boundary — the declared length and
    the running total — and either of them moving by one would start refusing a
    legitimate bundle of exactly `MAX_BUNDLE_BYTES`, which is a size a growing
    tenant arrives at rather than an attack.
    """
    body = json.dumps(bundle("v1")).encode()

    h = holder(httpx.Response(200, content=body), max_bytes=len(body))
    outcome = await h.refresh()

    assert outcome.kind == "replaced"
    assert h.current().version == "v1"


@pytest.mark.parametrize("declared", ["gzip", "GZIP", " Gzip", "gzip "])
@pytest.mark.asyncio
async def test_a_compressed_bundle_is_read(declared: str) -> None:
    """Compression is not refused, and this is why it cannot be.

    `RAIL_CENTER_URL` points at a Cloud Run service whose frontend may gzip a
    response of its own accord. A gateway that refused every encoded bundle
    would refuse every bundle, which is a worse failure than the one the bound
    exists for.

    Whatever spelling it arrives in. `Content-Encoding` is case-insensitive per
    RFC 9110, while the dispatch turns on an exact match against what this
    gateway offered — so a compliant peer answering `GZIP` for the very
    encoding this holder asked for would be refused as one it never offered,
    and every fetch would fail that way for the life of the process.
    """
    body = gzip.compress(json.dumps(bundle("v1")).encode())

    h = holder(streamed(body, declared))
    outcome = await h.refresh()

    assert outcome.kind == "replaced"
    assert h.current().version == "v1"


@pytest.mark.asyncio
async def test_a_compressed_body_is_bounded_where_it_decodes() -> None:
    """The bound is on what arrives, not on what the wire carried.

    Decoding is transparent, so a running total over already-decoded chunks
    bounds what is *accumulated* and not what one chunk costs: a body a
    fraction of the bound on the wire expands by whatever ratio the responder
    chose, and is allocated whole before anything counts it. Measured rather
    than asserted through the outcome, because the refusal reads the same
    either way — what changes is how much was committed to reach it.
    """
    size = 32 * 1024 * 1024
    body = gzip.compress(b'{"padding":"' + b"A" * size + b'"}')
    limit = 256 * 1024
    assert len(body) < limit, "the wire size has to walk past the bound on its own"

    h = holder(
        httpx.Response(200, json=bundle("v1")),
        streamed(body, "gzip"),
        max_bytes=limit,
    )
    await h.refresh()

    tracemalloc.start()
    try:
        outcome = await h.refresh()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert outcome.kind == "unreachable"
    assert f"decodes past the {limit}" in outcome.reason
    assert h.current().version == "v1"
    assert peak < size // 8


@pytest.mark.asyncio
async def test_the_decode_budget_allocates_one_byte_past_the_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The budget is what makes the refusal and the truncation inseparable.

    The measurement above is a memory proxy with megabytes of tolerance, so a
    per-chunk budget wrong by kilobytes never moves it. What the budget buys is
    exact: a capped call lands the decoded total at precisely one past the
    bound and so trips the refusal in the same iteration it overruns, which is
    why the surplus the decompressor still holds is never asked for.
    """
    produced: list[int] = []
    decompressobj = zlib.decompressobj

    class Counting:
        """`zlib`, with what each capped `decompress` actually produced."""

        @staticmethod
        def decompressobj(wbits: int) -> Any:
            inner = decompressobj(wbits)

            class Counted:
                @staticmethod
                def decompress(data: bytes, max_length: int = 0) -> bytes:
                    out = inner.decompress(data, max_length)
                    produced.append(len(out))
                    return out

            return Counted()

    monkeypatch.setattr(bundle_client, "zlib", Counting)

    body = gzip.compress(b'{"padding":"' + b"A" * (32 * 1024 * 1024) + b'"}')
    limit = 256 * 1024

    h = holder(streamed(body, "gzip"), max_bytes=limit)
    outcome = await h.refresh()

    assert outcome.kind == "unreachable"
    assert f"decodes past the {limit}" in outcome.reason
    assert sum(produced) == limit + 1


@pytest.mark.asyncio
async def test_a_body_that_decodes_past_the_bound_across_chunks_is_refused() -> None:
    """A bomb does not have to arrive in one chunk to be one.

    The maximally repetitive payload above saturates the budget inside the
    first `decompress` call, so the refusal fires on chunk zero and the running
    decoded total is never carried across chunks at all. This payload is
    compressible enough to stay well under the bound on the wire and ordinary
    enough that no single chunk decodes past it — only the accumulation does,
    which is the half the bound exists for and the half nothing else here
    exercises.
    """
    words = [f"policy-{n:04d}" for n in range(256)]
    picked = random.Random(0)
    padding = " ".join(picked.choice(words) for _ in range(30_000))
    doc = json.dumps(dict(bundle("v2"), padding=padding)).encode()
    body = gzip.compress(doc)
    limit = 256 * 1024

    assert len(body) < limit, "the wire bound must not be what refuses this"
    assert len(doc) > limit, "the decoded total has to walk past the bound"
    per_chunk = 16 * 1024 * len(doc) / len(body)
    assert per_chunk < limit, "no single chunk may reach the bound on its own"

    h = holder(
        httpx.Response(200, json=bundle("v1")),
        streamed(body, "gzip"),
        max_bytes=limit,
    )
    await h.refresh()

    outcome = await h.refresh()

    assert outcome.kind == "unreachable"
    assert f"decodes past the {limit}" in outcome.reason
    assert h.current().version == "v1"


@pytest.mark.asyncio
async def test_an_encoding_this_gateway_did_not_offer_is_refused() -> None:
    """The offer and the decoder have to agree.

    The bound only holds over a body this holder decodes itself, so an encoding
    it cannot decode is a failed fetch rather than a body handed to somebody
    else to expand.
    """
    h = holder(
        httpx.Response(200, json=bundle("v1")),
        streamed(b"\x1b\x2a", "br"),
    )
    await h.refresh()

    outcome = await h.refresh()

    assert outcome.kind == "unreachable"
    assert "br-encoded" in outcome.reason
    assert h.current().version == "v1"


@pytest.mark.asyncio
async def test_a_body_that_never_ends_is_bounded_by_the_deadline() -> None:
    """A drip is not a silence, and only the deadline tells them apart.

    httpx applies its own timeout per socket read and restarts it on every
    byte, so a responder sending one byte at a time inside it holds the read
    open indefinitely — and because `refresh()` serialises on a lock and
    `_loop` awaits it in sequence, that one open socket freezes every later
    refresh. What is held stays held throughout: this is a failed fetch like
    any other, not a reason to clear anything.
    """

    async def drip():
        while True:
            await asyncio.sleep(0.005)
            yield b" "

    h = holder(
        httpx.Response(200, json=bundle("v1")),
        httpx.Response(200, content=drip()),
        timeout_seconds=30.0,
        deadline_seconds=0.2,
    )
    assert (await h.refresh()).kind == "replaced"

    outcome = await h.refresh()

    assert outcome.kind == "unreachable"
    assert "0.2 seconds" in outcome.reason
    assert h.current().version == "v1"


@pytest.mark.asyncio
async def test_a_holder_given_no_deadline_bounds_the_attempt_at_the_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The deadline a deployment gets is the one nothing passes.

    Every other test here hands `deadline_seconds` in, and the refusal names
    `self._deadline` rather than the value the bound was actually applied with
    — so both the constructor default and the argument handed to `wait_for`
    can drift without a single assertion moving. What drifts with them is the
    whole-attempt bound: a shipped holder would hold the refresh lock against a
    drip responder for as long as the drift says, silently, and the message
    would still read thirty seconds.
    """
    applied: list[float] = []

    class Recording:
        """`asyncio`, with the deadline `_fetch` applies written down."""

        def __getattr__(self, name: str) -> Any:
            return getattr(asyncio, name)

        async def wait_for(self, awaitable: Any, timeout: float) -> Any:
            applied.append(timeout)
            return await asyncio.wait_for(awaitable, timeout)

    monkeypatch.setattr(bundle_client, "asyncio", Recording())

    h = holder(httpx.Response(200, json=bundle("v1")))
    outcome = await h.refresh()

    assert outcome.kind == "replaced"
    assert applied == [FETCH_DEADLINE_SECONDS]


# --- what an operator is told ---------------------------------------------


@pytest.mark.asyncio
async def test_a_rejected_credential_says_so_distinctly() -> None:
    """Every later refresh fails the same way until the configuration changes.

    Naming it apart from a control plane having a bad minute is what stops an
    operator waiting for it to clear.
    """
    h = holder(httpx.Response(401))
    outcome = await h.refresh()

    assert "rejected the credential (401)" in outcome.reason
    assert "RAIL_AUTH_MODE" in outcome.reason


@pytest.mark.asyncio
async def test_a_failure_is_a_warning_while_a_bundle_is_held(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """And an error once nothing is, because that is the state nothing resolves.

    The gateway with a stale ruleset still holds one, and `/ready` answers 200
    throughout. The gateway with none answers 503 for as long as this keeps
    failing, which is indefinitely — a refresh is the only thing that ends it,
    and a refresh is what just failed. So the second is the one an operator has
    to act on, and logging both at one level makes it invisible among the first.
    """
    with caplog.at_level(logging.WARNING, logger="gateway.bundle"):
        cold = holder(httpx.Response(503))
        await cold.refresh()
        levels_cold = [r.levelno for r in caplog.records]

        caplog.clear()
        warm = holder(httpx.Response(200, json=bundle("v1")), httpx.Response(503))
        await warm.refresh()
        await warm.refresh()
        levels_warm = [r.levelno for r in caplog.records]

    assert logging.ERROR in levels_cold
    assert levels_warm and max(levels_warm) == logging.WARNING


@pytest.mark.asyncio
async def test_a_rejected_policy_is_named_every_time_the_bundle_changes(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """`rejected` is not an error channel to drop.

    It names what Rail Center could not compile, so a gateway that swallows it
    enforces a chain narrower than the operator wrote with nothing on either
    side saying so.
    """
    rejected = [
        {"policy_id": TWO, "policy_name": "P2", "reason": "condition not evaluable"}
    ]
    h = holder(httpx.Response(200, json=bundle("v1", rejected=rejected)))
    with caplog.at_level(logging.WARNING, logger="gateway.bundle"):
        await h.refresh()

    said = "\n".join(r.getMessage() for r in caplog.records)
    assert "P2" in said
    assert TWO in said
    assert "condition not evaluable" in said
    assert "not in force" in said


@pytest.mark.parametrize("field", ["policy_name", "policy_id", "reason"])
@pytest.mark.asyncio
async def test_a_rejected_entry_cannot_forge_a_log_line(
    caplog: pytest.LogCaptureFixture, field: str
) -> None:
    """`rejected` is the one thing in a bundle that validation does not inspect.

    `validate_bundle` checks that it is a list and never looks inside an entry,
    so all three of these reach `logger.warning` raw off the wire — unlike
    `version`, which is refused upstream. `safe_for_log` on each is the only
    guard there is, which makes this the one log-injection defence in the file
    with nothing behind it.
    """
    from gateway.key_safety import has_unsafe_key_characters

    forged = "innocent\n2026-08-29 ERROR nothing was rejected\x1b[31m"
    entry = {"policy_id": TWO, "policy_name": "P2", "reason": "unevaluable"}
    entry[field] = forged

    h = holder(httpx.Response(200, json=bundle("v1", rejected=[entry])))
    with caplog.at_level(logging.WARNING, logger="gateway.bundle"):
        await h.refresh()

    said = "\n".join(r.getMessage() for r in caplog.records)
    assert not has_unsafe_key_characters(said)
    assert "ERROR nothing was rejected" not in said
    assert "<unprintable>" in said


@pytest.mark.asyncio
async def test_a_reason_never_carries_a_character_a_log_line_cannot_hold() -> None:
    """A malformed response puts its own bytes in the failure's text.

    h11 quotes what it could not parse — `illegal header line: b'...'` — so a
    control plane that has been tampered with could otherwise forge a log line
    through the first failed refresh. Python's JSON decoder does not do this; it
    reports a line and column, which is why the case that reaches the guard is a
    protocol error rather than a decode error.
    """
    from gateway.key_safety import has_unsafe_key_characters

    h = holder(
        httpx.RemoteProtocolError(
            "illegal header line: b'X-Forged: real\n2026-08-29 ERROR nothing\x1b[31m'"
        )
    )
    outcome = await h.refresh()

    assert outcome.kind == "unreachable"
    assert not has_unsafe_key_characters(outcome.reason)
    assert "unprintable" in outcome.reason


# --- the request itself ---------------------------------------------------


def test_a_header_value_that_cannot_be_sent_is_refused_at_the_constructor() -> None:
    """h11 refuses one by quoting the value it could not send.

    That reason reaches the log on every failed refresh, and `safe_for_log`
    does not catch it: `repr` has already flattened the control byte into two
    printable characters, so nothing unsafe is left to see and an
    `Authorization` value would be logged whole, once per refresh interval, for
    as long as the misconfiguration stood. The refusal here names the header
    and not the value.
    """
    secret = "Bearer s3cr3t-b\nearer-abc123XYZ"

    with pytest.raises(ValueError) as caught:
        BundleHolder("http://rc.test", {"Authorization": secret})

    said = str(caught.value)
    assert "Authorization" in said
    assert "U+000A" in said
    assert "s3cr3t" not in said


def test_an_ordinary_credential_still_travels() -> None:
    """The guard is not `auth.py`'s, which governs a bare token.

    `Bearer t0ken` carries a space, legal between the parts of a header value
    and illegal inside a credential, so the stricter rule here would refuse
    every request this gateway makes.
    """
    h = BundleHolder("http://rc.test", {"Authorization": "Bearer t0ken"})

    assert h._headers["Authorization"] == "Bearer t0ken"


@pytest.mark.asyncio
async def test_the_credential_and_the_route_travel_with_the_request() -> None:
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=bundle("v1"))

    h = BundleHolder(
        "http://rail-center.test/",
        {"Authorization": "Bearer t0ken"},
        transport=httpx.MockTransport(handle),
    )
    await h.refresh()

    assert str(seen[0].url) == f"http://rail-center.test{BUNDLE_PATH}"
    assert seen[0].headers["authorization"] == "Bearer t0ken"
    assert seen[0].headers["accept"] == "application/json"
    # What is offered is what this holder can decode under its own bound, so
    # httpx is not left to offer the encodings it can decode and this cannot.
    assert seen[0].headers["accept-encoding"] == "gzip, identity"


@pytest.mark.parametrize(
    "configured", ["http://rc.test", "http://rc.test/", "http://rc.test///"]
)
@pytest.mark.asyncio
async def test_a_trailing_slash_does_not_double_the_path(configured: str) -> None:
    seen: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json=bundle("v1"))

    await BundleHolder(configured, {}, transport=httpx.MockTransport(handle)).refresh()

    assert seen == [f"http://rc.test{BUNDLE_PATH}"]


@pytest.mark.asyncio
async def test_a_proxy_in_the_environment_does_not_redirect_the_fetch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`RAIL_CENTER_URL` is the whole of where this call may go.

    Left at its default, httpx reads `HTTP_PROXY` and `ALL_PROXY` out of the
    process environment — so whatever can set a variable in this container
    chooses the host that answers with the ruleset this gateway then enforces,
    and against an `http://` control plane sees the bearer token on the way
    past.
    """
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")

    built: list[httpx.AsyncClient] = []
    real = httpx.AsyncClient

    def record(**kwargs: Any) -> httpx.AsyncClient:
        client = real(**kwargs)
        built.append(client)
        return client

    monkeypatch.setattr(httpx, "AsyncClient", record)

    # No injected transport: httpx consults the environment only when it is
    # building its own, which is the shape every deployment runs.
    h = BundleHolder("http://127.0.0.1:1", {}, timeout_seconds=0.5)
    outcome = await h.refresh()

    assert outcome.kind == "unreachable"
    # A proxy httpx took from the environment arrives as a mount on the client.
    assert len(built) == 1 and not built[0]._mounts


@pytest.mark.asyncio
async def test_the_socket_timeout_reaches_the_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """What it bounds is a silence, and only this wires it to one.

    httpx applies this per socket read, so it is what a control plane that has
    stopped answering without closing the connection costs. Unwired, such a
    peer holds the refresh lock — and every refresh queued behind it — for the
    whole of `FETCH_DEADLINE_SECONDS` rather than for this.
    """
    built: list[httpx.AsyncClient] = []
    real = httpx.AsyncClient

    def record(**kwargs: Any) -> httpx.AsyncClient:
        client = real(**kwargs)
        built.append(client)
        return client

    monkeypatch.setattr(httpx, "AsyncClient", record)

    h = holder(httpx.Response(200, json=bundle("v1")), timeout_seconds=1.5)
    outcome = await h.refresh()

    assert outcome.kind == "replaced"
    assert len(built) == 1 and built[0].timeout == httpx.Timeout(1.5)


# --- the refresh loop -----------------------------------------------------


@pytest.mark.asyncio
async def test_start_returns_after_the_first_attempt_even_when_it_failed() -> None:
    """A gateway holding no bundle still starts, and still listens.

    It forwards every request unjudged while the loop keeps trying, and reports
    on `/ready` that it is holding nothing — a state an operator can see and act
    on. Refusing to start would turn a control plane that is briefly down into a
    gateway that never comes up.
    """
    ticks: list[float] = []

    async def sleep(seconds: float) -> None:
        ticks.append(seconds)
        await asyncio.sleep(0)

    h = holder(httpx.Response(503), httpx.Response(200, json=bundle("v1")), sleep=sleep)
    outcome = await h.start()
    assert outcome.kind == "unreachable"
    assert h.current() is None

    await asyncio.sleep(0)
    await asyncio.sleep(0)
    await h.stop()

    assert h.current() is not None
    assert ticks[0] == DEFAULT_REFRESH_SECONDS


@pytest.mark.asyncio
async def test_the_loop_survives_an_attempt_that_raises() -> None:
    """A loop that dies leaves the gateway enforcing what it last held, for ever.

    `_refresh_once` turns every expected failure into an outcome, so reaching
    the handler means something unforeseen — and continuing is right either way,
    because the alternative is silence after one traceback.
    """
    calls = {"n": 0}

    async def sleep(_seconds: float) -> None:
        await asyncio.sleep(0)

    h = holder(sleep=sleep)

    async def refresh_that_breaks_once():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("something unforeseen")
        from gateway.bundle.client import RefreshOutcome

        return RefreshOutcome("unreachable", None)

    h.refresh = refresh_that_breaks_once  # type: ignore[method-assign]
    h._task = asyncio.create_task(h._loop(h._epoch))
    for _ in range(8):
        await asyncio.sleep(0)
    await h.stop()

    assert calls["n"] > 1


@pytest.mark.asyncio
async def test_starting_twice_leaves_one_loop() -> None:
    """Overwriting `_task` would drop the only handle to the first loop.

    Nothing could then cancel it: it would keep refreshing for the life of the
    process, contending for the lock and doubling the load on the control
    plane, while `stop()` reported success having cancelled the second.
    """

    async def never(_seconds: float) -> None:
        # The loop parks here, so neither start's fetch is the loop's.
        await asyncio.Event().wait()

    h = holder(
        httpx.Response(200, json=bundle("v1")),
        httpx.Response(200, json=bundle("v1")),
        sleep=never,
    )
    await h.start()
    first = h._task
    assert first is not None

    await h.start()

    assert h._task is first
    assert not first.done()
    await h.stop()


@pytest.mark.asyncio
async def test_stopping_is_safe_before_starting_and_twice() -> None:
    h = holder()
    await h.stop()
    await h.stop()


@pytest.mark.asyncio
async def test_a_stopped_holder_starts_again() -> None:
    """`stop()` ends the loop it was called on, not every loop after it.

    The two halves of the lifecycle are each observed alone — a stop landing
    during a first fetch, and a second start leaving one loop — and a restart
    is where they meet. A shutdown that outlived its own call would leave a
    gateway with no refresh loop at all: still enforcing whatever it last held,
    never learning of a newer bundle, for the life of the process. Silent, and
    green.
    """

    async def never(_seconds: float) -> None:
        # The loop parks here, so no start's fetch is ever the loop's.
        await asyncio.Event().wait()

    h = holder(
        httpx.Response(200, json=bundle("v1")),
        httpx.Response(200, json=bundle("v1")),
        sleep=never,
    )
    await h.start()
    await h.stop()
    assert h._task is None

    await h.start()

    assert h._task is not None
    assert not h._task.done()
    await h.stop()


@pytest.mark.asyncio
async def test_a_stop_during_the_first_fetch_leaves_no_loop_behind() -> None:
    """`start()` has no task to cancel until its first fetch resolves.

    A shutdown landing in that window has nothing to act on, and a `stop()`
    that returned having done nothing would leave `start()` free to create the
    loop straight afterwards — a background refresh outliving an explicit,
    already-returned stop, with nothing holding a handle to cancel it.
    """
    reached = asyncio.Event()
    release = asyncio.Event()

    async def handle(_request: httpx.Request) -> httpx.Response:
        reached.set()
        await release.wait()
        return httpx.Response(200, json=bundle("v1"))

    h = BundleHolder("http://rc.test", {}, transport=httpx.MockTransport(handle))
    starting = asyncio.create_task(h.start())
    await reached.wait()

    await h.stop()
    release.set()
    outcome = await starting

    # The fetch still counted: what it brought back is held, and only the loop
    # was called off.
    assert outcome.kind == "replaced"
    assert h.current().version == "v1"
    assert h._task is None


@pytest.mark.asyncio
async def test_a_concurrent_start_cannot_erase_a_stop_that_landed() -> None:
    """Two `start()`s and a `stop()` are each documented as legitimate.

    So a shutdown can land between them, and the state that carries it has to
    survive the next caller. One flag shared by everybody does not: the second
    `start()` clears it on the way in, and the first is then free to create the
    loop the stop had already called off — a background refresh outliving an
    explicit, fully-awaited shutdown. An epoch belongs to the call that
    captured it, so only the start issued after the stop can start anything.
    """
    reached = [asyncio.Event(), asyncio.Event()]
    release = [asyncio.Event(), asyncio.Event()]
    seen = 0

    async def handle(_request: httpx.Request) -> httpx.Response:
        nonlocal seen
        n = seen
        seen += 1
        reached[n].set()
        await release[n].wait()
        return httpx.Response(200, json=bundle("v1"))

    h = BundleHolder("http://rc.test", {}, transport=httpx.MockTransport(handle))
    first = asyncio.create_task(h.start())
    await reached[0].wait()

    await h.stop()
    # Entering while the first start's fetch is still in flight, which is the
    # window the stop has no task to act on.
    second = asyncio.create_task(h.start())
    release[0].set()
    await first

    # The second start is still inside its own fetch, so a loop here could only
    # be the first one's — the one the stop called off.
    assert h._task is None

    release[1].set()
    await second

    # And the start issued after the stop is unaffected: it owns the loop.
    assert h._task is not None
    await h.stop()


@pytest.mark.asyncio
async def test_two_refreshes_never_run_at_once() -> None:
    """Serialised on a lock, and this is the only place that is observable.

    A scheduled refresh and a manual one can be asked for at the same moment.
    Two in flight double the load on the control plane and interleave their
    reads and writes of what is held — the second could validate an older body
    and overwrite the newer bundle the first had just stored.
    """
    depth = 0
    overlapped = False

    async def handle(_request: httpx.Request) -> httpx.Response:
        nonlocal depth, overlapped
        depth += 1
        overlapped = overlapped or depth > 1
        # A suspension point inside the fetch, which is where a second refresh
        # would get in if nothing held it back.
        await asyncio.sleep(0)
        depth -= 1
        return httpx.Response(200, json=bundle("v1"))

    h = BundleHolder("http://rc.test", {}, transport=httpx.MockTransport(handle))
    outcomes = await asyncio.gather(h.refresh(), h.refresh())

    assert not overlapped
    assert [o.kind for o in outcomes] == ["replaced", "unchanged"]


# --- the interval ---------------------------------------------------------


def test_the_interval_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sixty as a literal, so the number is what is asserted.

    Written as the constant it would hold for any value of it, and the value is
    the claim: an operator is told a policy change reaches enforcement within a
    minute.
    """
    monkeypatch.delenv("RAIL_GATEWAY_BUNDLE_REFRESH_SECONDS", raising=False)
    assert DEFAULT_REFRESH_SECONDS == 60
    assert MIN_REFRESH_SECONDS == 5
    assert refresh_seconds() == 60


@pytest.mark.parametrize("value", ["5", "60", "3600", " 120 "])
def test_an_interval_at_or_above_the_floor_is_taken(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, value: str
) -> None:
    """The floor itself is taken, and taken silently.

    `5` is the boundary: at it the floor and the configured value are the same
    number, so only the absence of the warning distinguishes a value that was
    accepted from one that was overruled.
    """
    monkeypatch.setenv("RAIL_GATEWAY_BUNDLE_REFRESH_SECONDS", value)
    with caplog.at_level(logging.WARNING, logger="gateway.bundle"):
        assert refresh_seconds() == int(value.strip())

    assert caplog.records == []


@pytest.mark.parametrize("value", ["1", "0", "-30", "4"])
def test_an_interval_below_the_floor_is_raised_rather_than_refused(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, value: str
) -> None:
    """Overruled, not fatal — and never silently.

    A number that cannot be read at all is a typo and stops the process; one
    that is merely too eager is a judgement this component is entitled to
    overrule, and refusing to start over it would take enforcement down to
    protect the control plane from load. Overruling an operator without saying
    so is the failure the warning exists to prevent, so the warning is half of
    the contract and is asserted as such.
    """
    monkeypatch.setenv("RAIL_GATEWAY_BUNDLE_REFRESH_SECONDS", value)
    with caplog.at_level(logging.WARNING, logger="gateway.bundle"):
        assert refresh_seconds() == MIN_REFRESH_SECONDS

    said = "\n".join(r.getMessage() for r in caplog.records)
    assert "RAIL_GATEWAY_BUNDLE_REFRESH_SECONDS" in said
    assert f"below the floor of {MIN_REFRESH_SECONDS}" in said
    assert f"using {MIN_REFRESH_SECONDS}" in said


@pytest.mark.parametrize("value", ["sixty", "60s", "6.0", ""])
def test_an_interval_that_is_not_a_number(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("RAIL_GATEWAY_BUNDLE_REFRESH_SECONDS", value)
    if not value:
        assert refresh_seconds() == DEFAULT_REFRESH_SECONDS
        return
    with pytest.raises(RuntimeError) as caught:
        refresh_seconds()
    assert "must be an integer" in str(caught.value)
