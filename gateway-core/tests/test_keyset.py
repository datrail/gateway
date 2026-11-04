"""Holding Rail Center's key set, and every way of failing to.

The rule under test is the contract's, in rail-center's
`docs/policy-evaluation-contract.md` ("A signed ticket"): **a key set is held
only as fetched from `RAIL_CENTER_URL` + `/v1/jwks.json`, over HTTPS, and only
for the maximum key-set age after the last fetch that succeeded.** Unlike the
policy bundle, which is kept however old it is, a key set past that age is not
held at all, because that age is what makes withdrawing a key reach a gateway
that cannot reach Rail Center.

So every case asks what the verifier holds afterwards, and not only what the
outcome says: a holder that reported a failure honestly while clearing a good
set, or kept a stale one past its age, is the bug this file exists to catch.
"""

import asyncio
import json
import logging
from dataclasses import replace
from typing import Any

import httpx
import pytest
from test_signed_ticket import AUDIENCE, ISSUER, KID, NOW, SIGNING, _claims, _signed

import gateway.core.keyset as keyset_module
from gateway.core.keyset import (
    FETCH_DEADLINE_SECONDS,
    JWKS_PATH,
    MAX_JWKS_BYTES,
    MAX_KEY_SET_AGE_SECONDS,
    REFRESH_SECONDS,
    UNKNOWN_KID_REFETCH_SECONDS,
    KeySetHolder,
)
from gateway.core.ticket import parse_rail_header

URL = "https://rail-center.example"
JWKS = SIGNING["jwks"]
OTHER_ENTRY = {**JWKS["keys"][0], "kid": "vector-key-2"}


class Clock:
    """A clock the test moves, standing in for the boot-time clock."""

    def __init__(self, at: float = 1000.0) -> None:
        self.at = at

    def __call__(self) -> float:
        return self.at


def responder(*answers: httpx.Response | Exception, seen: list | None = None):
    """A Rail Center answering each request with the next thing given.

    Running out is a test bug rather than a scenario, so it raises: a holder
    fetching more often than a case expects would otherwise pass quietly.
    """
    remaining = list(answers)

    def handle(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        if not remaining:
            raise AssertionError("the holder fetched more times than the test supplied")
        answer = remaining.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    return httpx.MockTransport(handle)


def ok(body: Any = JWKS) -> httpx.Response:
    return httpx.Response(200, json=body)


def holder(
    transport, clock: Clock | None = None, url: str = URL, **kwargs
) -> KeySetHolder:
    return KeySetHolder(
        url,
        {"Authorization": "Bearer t0ken"},
        transport=transport,
        clock=clock or Clock(),
        **kwargs,
    )


def valid_ticket() -> str:
    return _signed(_claims())


def reads(keys: KeySetHolder, header: str) -> str:
    # The holder supplies keys alone. The issuer and audience are the vectors'
    # tenant's, as a reader holding them would compare against, so what these
    # tests tell apart is the key set: `valid` against `bad_signature`.
    verifier = replace(keys.verifier(), issuer=ISSUER, audience=AUDIENCE)
    return parse_rail_header(header, NOW, verifier).state


@pytest.mark.asyncio
async def test_a_fetched_set_verifies_a_ticket_its_key_signed() -> None:
    keys = holder(responder(ok()))

    outcome = await keys.refresh()

    assert outcome.kind == "replaced"
    assert reads(keys, valid_ticket()) == "valid"


@pytest.mark.asyncio
async def test_nothing_is_held_before_the_first_fetch() -> None:
    keys = holder(responder())

    assert keys.verifier().keys is None
    assert reads(keys, valid_ticket()) == "bad_signature"


@pytest.mark.asyncio
async def test_the_fetch_is_the_jwks_route_with_the_gateways_own_credential() -> None:
    seen: list[httpx.Request] = []
    keys = holder(responder(ok(), seen=seen), url=URL + "/")

    await keys.refresh()

    (request,) = seen
    assert str(request.url) == URL + JWKS_PATH
    assert request.headers["authorization"] == "Bearer t0ken"
    assert request.headers["cache-control"] == "no-cache"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answer",
    [
        httpx.Response(401),
        httpx.Response(403),
        httpx.Response(500),
        httpx.Response(200, content=b"not json"),
        httpx.Response(200, json={"keys": []}),
        httpx.Response(200, json={"keys": [JWKS["keys"][0], JWKS["keys"][0]]}),
        httpx.Response(200, json=[JWKS["keys"][0]]),
        httpx.Response(
            200,
            content=json.dumps({**JWKS, "note": 0}).replace("0}", "NaN}").encode(),
        ),
        httpx.ConnectError("refused"),
    ],
    ids=[
        "401",
        "403",
        "500",
        "not JSON",
        "no usable key",
        "a repeated kid",
        "not an object",
        "a NaN, which is not JSON",
        "unreachable",
    ],
)
async def test_a_failed_fetch_replaces_nothing(answer) -> None:
    keys = holder(responder(ok(), answer))
    await keys.refresh()

    outcome = await keys.refresh()

    assert outcome.kind == "failed"
    assert reads(keys, valid_ticket()) == "valid"


@pytest.mark.asyncio
async def test_a_failed_first_fetch_holds_nothing() -> None:
    keys = holder(responder(httpx.Response(401)))

    outcome = await keys.refresh()

    assert outcome.kind == "failed"
    assert keys.verifier().keys is None


@pytest.mark.asyncio
async def test_a_successful_fetch_replaces_the_whole_set() -> None:
    """A `kid` absent from the latest set is no longer held, which is what
    makes withdrawing a key take effect."""
    keys = holder(responder(ok(), ok({"keys": [OTHER_ENTRY]})))
    await keys.refresh()

    await keys.refresh()

    assert set(keys.verifier().keys or {}) == {"vector-key-2"}
    assert reads(keys, valid_ticket()) == "bad_signature"


@pytest.mark.asyncio
async def test_a_redirect_is_not_followed() -> None:
    seen: list[httpx.Request] = []
    keys = holder(
        responder(
            httpx.Response(302, headers={"location": "https://elsewhere.example/jwks"}),
            seen=seen,
        )
    )

    outcome = await keys.refresh()

    assert outcome.kind == "failed"
    assert len(seen) == 1
    assert keys.verifier().keys is None


@pytest.mark.asyncio
async def test_an_http_rail_center_is_never_fetched(caplog) -> None:
    """The set must come over HTTPS with the certificate checked. Over plain
    HTTP anyone on the path chooses the keys this gateway trusts."""
    caplog.set_level(logging.WARNING)
    keys = holder(responder(), url="http://rail-center.example")

    started = await keys.start()
    await keys.ensure(valid_ticket())
    refreshed = await keys.refresh()

    assert (started.kind, refreshed.kind) == ("failed", "failed")
    assert keys.verifier().keys is None
    assert "not https://" in caplog.text
    await keys.stop()


@pytest.mark.asyncio
async def test_a_body_declared_past_the_bound_is_refused_unread() -> None:
    body = json.dumps(JWKS).encode()
    keys = holder(
        responder(
            httpx.Response(
                200, content=body, headers={"content-length": str(MAX_JWKS_BYTES + 1)}
            )
        )
    )

    outcome = await keys.refresh()

    assert outcome.kind == "failed"
    assert keys.verifier().keys is None


@pytest.mark.asyncio
async def test_a_body_past_the_bound_is_refused_as_it_streams() -> None:
    padding = " " * MAX_JWKS_BYTES
    body = (json.dumps(JWKS)[:-1] + padding + "}").encode()

    async def chunks():
        for start in range(0, len(body), 4096):
            yield body[start : start + 4096]

    keys = holder(responder(httpx.Response(200, content=chunks())))

    outcome = await keys.refresh()

    assert outcome.kind == "failed"
    assert keys.verifier().keys is None


@pytest.mark.asyncio
async def test_a_fetch_past_the_deadline_is_a_failed_fetch(monkeypatch) -> None:
    class Stalled(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            await asyncio.sleep(3600)

    keys = holder(Stalled(), deadline_seconds=0.05)

    outcome = await keys.refresh()

    assert outcome.kind == "failed"
    assert keys.verifier().keys is None
    assert FETCH_DEADLINE_SECONDS == 10.0


@pytest.mark.asyncio
async def test_a_set_past_its_maximum_age_is_not_held() -> None:
    clock = Clock()
    keys = holder(responder(ok()), clock)
    await keys.refresh()

    clock.at += MAX_KEY_SET_AGE_SECONDS
    assert reads(keys, valid_ticket()) == "valid"

    clock.at += 1
    assert keys.verifier().keys is None
    assert reads(keys, valid_ticket()) == "bad_signature"


@pytest.mark.asyncio
async def test_a_failed_fetch_does_not_restart_the_age() -> None:
    """Age is counted from the last fetch that succeeded, so a run of failures
    leaves the set to age out on time."""
    clock = Clock()
    keys = holder(responder(ok(), httpx.Response(500)), clock)
    await keys.refresh()

    clock.at += MAX_KEY_SET_AGE_SECONDS - 1
    await keys.refresh()
    clock.at += 2

    assert keys.verifier().keys is None


@pytest.mark.asyncio
async def test_an_unknown_kid_is_refetched_before_the_ticket_is_read() -> None:
    """A key that signs at once — a compromise withdrawal's replacement — is
    published at the same moment it signs, so its first tickets name a `kid`
    the gateway does not yet hold. The request waits for one refetch."""
    clock = Clock()
    keys = holder(responder(ok({"keys": [OTHER_ENTRY]}), ok()), clock)
    await keys.refresh()
    clock.at += UNKNOWN_KID_REFETCH_SECONDS

    await keys.ensure(valid_ticket())

    assert reads(keys, valid_ticket()) == "valid"


@pytest.mark.asyncio
async def test_unknown_kids_are_refetched_at_most_once_per_interval() -> None:
    """A stream of invented `kid`s must not become a stream of fetches."""
    clock = Clock()
    seen: list[httpx.Request] = []
    stale = {"keys": [OTHER_ENTRY]}
    keys = holder(responder(ok(stale), ok(stale), ok(stale), seen=seen), clock)
    await keys.refresh()
    clock.at += UNKNOWN_KID_REFETCH_SECONDS

    await keys.ensure(valid_ticket())
    clock.at += UNKNOWN_KID_REFETCH_SECONDS - 1
    await keys.ensure(valid_ticket())

    # Counted, not left to the responder running out: the holder turns any
    # raise inside a fetch into a failed fetch, so an extra one would not show.
    assert len(seen) == 2
    clock.at += 1
    await keys.ensure(valid_ticket())
    assert len(seen) == 3


@pytest.mark.asyncio
async def test_concurrent_requests_naming_an_unknown_kid_share_one_fetch() -> None:
    clock = Clock()
    seen: list[httpx.Request] = []
    keys = holder(responder(ok({"keys": [OTHER_ENTRY]}), ok(), seen=seen), clock)
    await keys.refresh()
    clock.at += UNKNOWN_KID_REFETCH_SECONDS

    async def request() -> str:
        # Read straight after its own `ensure`, as a request would: one that
        # returned without waiting for the fetch in flight reads the old set.
        await keys.ensure(valid_ticket())
        return reads(keys, valid_ticket())

    states = await asyncio.gather(*(request() for _ in range(5)))

    assert states == ["valid"] * 5
    assert len(seen) == 2


@pytest.mark.asyncio
async def test_stop_retires_a_refetch_in_flight() -> None:
    """A refetch an unknown `kid` started ends with the holder: `stop()` does not
    wait on it, it does not replace the set afterwards, and the request waiting
    on it returns, to read its ticket against the set held, rather than being
    cancelled."""
    started = asyncio.Event()
    release = asyncio.Event()

    class Held(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            started.set()
            await release.wait()
            return ok()

    keys = holder(Held())
    waiting = asyncio.create_task(keys.ensure(valid_ticket()))
    await asyncio.wait_for(started.wait(), 5)

    await asyncio.wait_for(keys.stop(), 5)
    release.set()
    await asyncio.wait_for(waiting, 5)
    await asyncio.sleep(0)

    assert keys.verifier().keys is None
    assert reads(keys, valid_ticket()) == "bad_signature"


@pytest.mark.asyncio
async def test_stop_does_not_raise_a_refetch_that_ended_on_a_defect(
    monkeypatch, caplog
) -> None:
    """After this, teardown says a refused start's second raise and cancels a
    first fetch not yet read, so a defect the refetch ended on is logged here
    rather than raised into it."""

    def broken(_body):
        raise RuntimeError("defect")

    monkeypatch.setattr(keyset_module, "usable_keys", broken)
    keys = holder(responder(ok()))
    await keys.ensure(valid_ticket())

    with caplog.at_level(logging.ERROR, logger="gateway.core.keyset"):
        await keys.stop()

    assert "a signing key set fetch raised before it was stopped" in caplog.text


@pytest.mark.asyncio
async def test_a_held_kid_or_an_unsigned_ticket_fetches_nothing() -> None:
    keys = holder(responder(ok()))
    await keys.refresh()

    await keys.ensure(valid_ticket())
    await keys.ensure("eyJleHAiOjF9")
    await keys.ensure(None)


@pytest.mark.asyncio
async def test_holding_no_set_refetches_on_a_signed_ticket() -> None:
    """With nothing held, every `kid` is unknown: the first signed ticket asks
    for a set, within the same 30-second limit."""
    keys = holder(responder(ok()))

    await keys.ensure(valid_ticket())

    assert reads(keys, valid_ticket()) == "valid"


@pytest.mark.asyncio
async def test_a_refetch_that_raises_leaves_the_ticket_refused(
    monkeypatch, caplog
) -> None:
    """The Apigee callout forwards a request whose handler raises, so a raise
    out of `ensure` would admit a ticket no key was checked against."""
    keys = holder(responder(ok({"keys": [OTHER_ENTRY]})))
    await keys.refresh()

    async def broken(_kid: str) -> None:
        raise RuntimeError("defect")

    monkeypatch.setattr(keys, "_refresh_for", broken)

    with caplog.at_level(logging.ERROR, logger="gateway.core.keyset"):
        await keys.ensure(valid_ticket())

    assert reads(keys, valid_ticket()) == "bad_signature"
    assert "the signing key set refetch raised" in caplog.text


@pytest.mark.asyncio
async def test_the_loop_refreshes_on_its_interval_and_stops() -> None:
    sleeps: list[float] = []
    done = asyncio.Event()

    async def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        if len(sleeps) > 1:
            done.set()
            await asyncio.sleep(3600)

    keys = holder(responder(ok(), ok()), sleep=sleep)

    await keys.start()
    await asyncio.wait_for(done.wait(), 5)
    await keys.stop()

    assert sleeps[0] == REFRESH_SECONDS
    assert keys.verifier().keys is not None


@pytest.mark.asyncio
async def test_the_verifier_carries_keys_alone() -> None:
    """The issuer and audience are the held bundle's, which `judge` adds; the
    key set's verifier carries none, and reads both forms."""
    keys = holder(responder(ok()))
    await keys.refresh()

    verifier = keys.verifier()

    assert set(verifier.keys or {}) == {KID}
    assert (verifier.issuer, verifier.audience, verifier.requires_signatures) == (
        None,
        None,
        False,
    )
    assert KID == "vector-key-1"


@pytest.mark.asyncio
async def test_a_refresh_in_flight_that_brings_the_key_spares_a_second_fetch() -> None:
    """A request naming a new `kid` while the periodic refresh is running waits
    for that refresh, and fetches again only if it did not bring the key: a
    second fetch would cost the request a second deadline for a set it has."""
    clock = Clock()
    release = asyncio.Event()
    seen: list[httpx.Request] = []
    answers = [ok({"keys": [OTHER_ENTRY]}), ok()]

    async def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if len(seen) == 2:
            await release.wait()
        return answers.pop(0)

    class Gated(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            return await handle(request)

    keys = holder(Gated(), clock)
    await keys.refresh()
    clock.at += UNKNOWN_KID_REFETCH_SECONDS

    periodic = asyncio.create_task(keys.refresh())
    while len(seen) < 2:
        await asyncio.sleep(0)
    waiting = asyncio.create_task(keys.ensure(valid_ticket()))
    await asyncio.sleep(0)
    release.set()
    await asyncio.gather(periodic, waiting)

    assert len(seen) == 2
    assert reads(keys, valid_ticket()) == "valid"
