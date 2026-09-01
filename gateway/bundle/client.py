"""Holding the policy bundle: fetch it, keep it, refresh it — and never mistake
a failed fetch for an empty ruleset.

One rule shapes the whole file, and it is the contract's:

> An enforcement point that cannot reach `GET /v1/policy-bundle` has no ruleset,
> which is not the same as an empty one. It must keep serving the last bundle it
> holds, and refuse traffic if it has never held one.

An empty chain **allows**, so treating a failed fetch as a bundle with no rules
turns an outage of the control plane into an outage of enforcement — every
request admitted, with nothing in the logs saying that is what happened. Every
failure path below therefore ends in one of two places: keep what is held, or
hold nothing and leave the caller to answer for it — which today means
reporting it on `/ready`, not refusing. `current()` is where that stands.

The network and the clock are injected. Everything they touch is small and
everything else is a pure function of what arrived, which is the only shape two
implementations can be compared on.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import zlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal

import httpx

from gateway.bundle.validate import UnusableBundle, UsableBundle, validate_bundle
from gateway.key_safety import safe_for_log

logger = logging.getLogger("gateway.bundle")

#: The route is the OpenAPI specification's, not a deployment's. Making it
#: configurable would add a way to misconfigure it and buy nothing; what a
#: deployment configures is `RAIL_CENTER_URL`.
BUNDLE_PATH = "/v1/policy-bundle"

#: How often to ask again, in seconds. **Chosen, not inherited** — neither the
#: contract nor the specification names an interval.
#:
#: Sixty because `version` is a content hash: an unchanged one costs a round trip
#: and a string comparison, cheap enough to do often, while a rule an operator
#: changes reaches enforcement within a minute — a number a person can be told.
#: Seconds would load the control plane for nothing; minutes would make "no
#: gateway release" feel untrue.
DEFAULT_REFRESH_SECONDS = 60

#: The floor under a configured interval. Not a default: a deployment asking for
#: one second is asking this gateway to spend a request per second per instance
#: on a document that changes when a person edits a policy. Five is low enough
#: that nobody who wants "fast" is denied it, and high enough that a typo cannot
#: turn a fleet into a load generator.
MIN_REFRESH_SECONDS = 5

#: How long one socket read may wait, in seconds. Five is far more than a
#: same-region round trip, and short enough that a control plane which has
#: stopped answering without closing the connection costs one refresh rather
#: than an unbounded wait.
#:
#: This is httpx's timeout, and httpx restarts it on every read that succeeds.
#: It therefore bounds a silence, not an attempt: a responder sending one byte
#: just inside it holds the read open for as long as it keeps sending. What
#: bounds the attempt is `FETCH_DEADLINE_SECONDS`.
FETCH_TIMEOUT_SECONDS = 5.0

#: The deadline on a whole fetch, in seconds.
#:
#: `refresh()` serialises on a lock and `_loop` awaits it in sequence, so an
#: attempt that never finishes stops every later one: the held bundle stays in
#: force and quietly stops being fresh, for the cost of one open socket held by
#: whoever answers as `RAIL_CENTER_URL`. This is what bounds that.
#:
#: Thirty rather than five, because it has to cover a whole `MAX_BUNDLE_BYTES`
#: body and not one read — four megabytes at 140 KiB/s arrives inside it, so a
#: slow link is not mistaken for a stalled one. Past it the attempt is
#: `unreachable` like any other, which keeps what is held.
FETCH_DEADLINE_SECONDS = 30.0

#: The largest bundle this gateway will read, in bytes.
#:
#: The deadline bounds how *long* a response may take and says nothing about how
#: *large* it may be: a control plane answering quickly with an enormous body
#: would otherwise be read whole. Four megabytes is far more than a tenant's
#: whole ruleset — a chain is a few dozen policies of a few hundred bytes — and
#: small enough that a body past it is a fault rather than a big customer. One
#: past it is treated as unreachable, so the last bundle held stays in force.
MAX_BUNDLE_BYTES = 4 * 1024 * 1024

#: What this gateway offers to decode, and the whole of what it accepts back.
#:
#: Compression is not refused. `RAIL_CENTER_URL` points at a Cloud Run service
#: whose frontend may gzip a response of its own accord, and a gateway that
#: refused every encoded bundle would refuse every bundle — a worse failure than
#: the one `MAX_BUNDLE_BYTES` is here for.
#:
#: What is refused is an encoding this holder did not offer, because the offer
#: and the decoder have to agree: the bound can only hold over a body this file
#: decodes itself.
_ACCEPT_ENCODING = "gzip, identity"

#: `zlib` reads a bare deflate stream by default; this asks for the gzip wrapper
#: that `Content-Encoding: gzip` names.
_GZIP_WINDOW = 16 + zlib.MAX_WBITS

#: What may not appear in a header value this holder sends.
#:
#: Deliberately not `auth.py`'s rule, which is stricter because it governs a
#: bearer token rather than a whole field value: `Bearer t0ken` carries a space,
#: which is legal between the parts of a value and illegal inside a credential.
_HEADER_VALUE_UNSAFE = re.compile(r"[^\x20-\x7E]")


def _sendable(headers: dict[str, str]) -> dict[str, str]:
    """`headers`, or a refusal naming the header and not its value.

    The value is checked here rather than left to the socket, because h11
    refuses one by raising `LocalProtocolError` **quoting the value it could not
    send** — and that reason reaches `_unreachable` on every failed refresh.
    `safe_for_log` does not catch it: `repr` has already flattened the offending
    control byte into two printable characters, so nothing unsafe is left to
    see, and an `Authorization` value would be logged whole, once per refresh
    interval, for as long as the misconfiguration stood.

    `auth_headers()` pre-filters the credential it produces, so today's only
    caller cannot get here. This constructor declares `dict[str, str]` and has
    to hold for what it declares.
    """
    for name, value in headers.items():
        found = _HEADER_VALUE_UNSAFE.search(value)
        if found is not None:
            offset = found.start()
            raise ValueError(
                f"header {safe_for_log(name)} holds "
                f"U+{ord(value[offset]):04X} at offset {offset}, "
                "which cannot go in a header value"
            )
        if value != value.strip():
            # h11 refuses a padded value too, and quotes it the same way.
            raise ValueError(
                f"header {safe_for_log(name)} is padded with whitespace, "
                "which cannot go in a header value"
            )
    return headers


def _reject_non_json_constant(name: str) -> Any:
    """Refuse `NaN`, `Infinity` and `-Infinity` in a fetched bundle.

    Named rather than a lambda so the `ValueError` it raises says which token
    was refused, and so `_fetch`'s comment has something to point at. The same
    guard sits on the ticket reader; both doors need it, because a number that
    is not JSON is a divergence wherever it enters.
    """
    raise ValueError(f"{name} is not JSON")


@dataclass(frozen=True)
class RefreshOutcome:
    """What one attempt produced — for the log line, and for a test to assert on.

    `kind` is the whole verdict; the rest is context.

    * ``unchanged``   the version matched what is held, so nothing was re-parsed
    * ``replaced``    a new bundle validated and is now held
    * ``unusable``    a bundle arrived and cannot be applied
    * ``unreachable`` nothing usable arrived at all

    The last two differ in where the fault is, and an operator needs to know
    which: `unusable` means Rail Center and this gateway have drifted and the
    log line names the offending policy, while `unreachable` means the network
    or the credential. Both keep what is held.
    """

    kind: Literal["unchanged", "replaced", "unusable", "unreachable"]
    #: The version now held, or None when nothing is.
    held: str | None
    #: Why, for the two failing kinds. Already passed through `safe_for_log`.
    reason: str | None = None


def refresh_seconds() -> int:
    """`RAIL_GATEWAY_BUNDLE_REFRESH_SECONDS`, floored.

    A value under the floor is raised to it with a warning rather than refused.
    The distinction is deliberate: a number that cannot be read at all is a
    typo and stops the process, while one that is merely too eager is a
    judgement this component is entitled to overrule, and refusing to start over
    it would take enforcement down to protect the control plane from load.
    """
    raw = (os.environ.get("RAIL_GATEWAY_BUNDLE_REFRESH_SECONDS") or "").strip()
    if not raw:
        return DEFAULT_REFRESH_SECONDS
    try:
        value = int(raw)
    except ValueError:
        raise RuntimeError(
            "RAIL_GATEWAY_BUNDLE_REFRESH_SECONDS must be an integer, "
            f"got: {safe_for_log(raw)}"
        ) from None
    if value < MIN_REFRESH_SECONDS:
        logger.warning(
            "RAIL_GATEWAY_BUNDLE_REFRESH_SECONDS is %d, below the floor of %d; "
            "using %d",
            value,
            MIN_REFRESH_SECONDS,
            MIN_REFRESH_SECONDS,
        )
        return MIN_REFRESH_SECONDS
    return value


class BundleHolder:
    """The policy bundle this gateway decides against, and how it stays current.

    Nothing here decides anything. It fetches, validates through
    `validate_bundle`, keeps what survives, and hands it back — so the one
    question a caller asks is `current()`, and `None` from that means *refuse*,
    never *allow*.
    """

    def __init__(
        self,
        rail_center_url: str,
        headers: dict[str, str],
        *,
        interval_seconds: int = DEFAULT_REFRESH_SECONDS,
        timeout_seconds: float = FETCH_TIMEOUT_SECONDS,
        deadline_seconds: float = FETCH_DEADLINE_SECONDS,
        max_bytes: int = MAX_BUNDLE_BYTES,
        # Injected so the tests need neither a network nor a wait. A caller that
        # passes neither gets the real ones.
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        self._url = rail_center_url.rstrip("/") + BUNDLE_PATH
        self._headers = _sendable(
            {
                "Accept": "application/json",
                **headers,
                # Last, so it is not the caller's to change: the bound on the
                # body is applied by the decoder that reads it, so what is
                # offered has to stay what this holder can count as it decodes.
                "Accept-Encoding": _ACCEPT_ENCODING,
            }
        )
        self._interval = interval_seconds
        self._timeout = timeout_seconds
        self._deadline = deadline_seconds
        self._max_bytes = max_bytes
        self._transport = transport
        self._sleep = sleep or asyncio.sleep

        self._held: UsableBundle | None = None
        self._task: asyncio.Task[None] | None = None
        # Bumped by `stop()`. `start()` captures it on entry and creates the
        # loop only if it is still current, which is what makes a stop landing
        # during a first fetch stick.
        self._epoch = 0
        self._lock = asyncio.Lock()

    def current(self) -> UsableBundle | None:
        """The bundle to decide against, or **None when none was ever held**.

        Never a bundle that failed validation, and never cleared by a failed
        fetch: the last usable bundle stays until a newer usable one replaces
        it. None is the contract's *refuse*, and it is not the same as a bundle
        with no policies, which allows. Two callers read it. Readiness reports
        it on `/ready`, where holding nothing is what makes the gateway not
        ready. `_judge` decides against it, and what it does with None is the
        mode's answer rather than this holder's: under `enforce`, the default,
        it refuses the request 503 without judging it, and under `observe` it
        forwards it unjudged. So a holder that has never held a bundle is
        refusing every call on an ordinary deployment — which is why nothing
        here may describe the absence of a bundle as harmless.
        """
        return self._held

    async def refresh(self) -> RefreshOutcome:
        """One attempt, whatever the outcome.

        Serialised on a lock rather than coalesced into a shared future: a
        caller asking for a refresh wants a fresh answer, and handing it the
        result of an attempt that started before it asked is a subtly different
        promise. The cost is that a manual refresh waits behind a scheduled one,
        which is bounded by the deadline.
        """
        async with self._lock:
            return await self._refresh_once()

    async def start(self) -> RefreshOutcome:
        """Fetch once, then keep refreshing in the background.

        Returns after the first attempt whether or not it succeeded. A gateway
        holding no bundle still starts and still listens, reports on `/ready`
        that it is holding nothing, and keeps trying — a state an operator can
        see and act on. Refusing to start would turn a control plane that is
        briefly down into a gateway that never comes up.

        **What happens to a request in that window is the caller's, not this
        module's, and it is not the same in every mode.** Under `enforce` a
        request that cannot be judged is refused; under `observe` it is
        forwarded and the fact that nothing judged it is logged. `current()`
        returning None is what both read, and neither answer is described here,
        because a holder that named one of them would be wrong in the other.

        Calling it twice refreshes twice and still leaves one loop. Overwriting
        `_task` instead would drop the only handle to the first, which nothing
        could then cancel: it would keep refreshing for the life of the process,
        contending for the lock and doubling the load on the control plane.

        A `stop()` landing while the first fetch is still in flight is honoured
        rather than lost. There is no task for it to cancel yet, so what it does
        instead is retire the epoch this call captured on entry, and the loop is
        created only while that epoch is still current — otherwise a shutdown
        racing a slow first fetch leaves a loop behind that has already been
        told to stop and that nothing holds a handle to.

        An epoch rather than a flag, because a flag is one bit shared by every
        caller: both calls above are documented as legitimate, so a second
        `start()` entering that same window clears it and erases a `stop()` that
        has already landed and already returned. An epoch belongs to the call
        that captured it, so no other call can hand this one back a shutdown
        that was called off.
        """
        epoch = self._epoch
        outcome = await self.refresh()
        if epoch == self._epoch and (self._task is None or self._task.done()):
            self._task = asyncio.create_task(self._loop(epoch))
        return outcome

    async def stop(self) -> None:
        """Stop refreshing. Safe to call twice, and safe with one in flight."""
        self._epoch += 1
        task, self._task = self._task, None
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    async def _loop(self, epoch: int) -> None:
        # What ends this loop is the epoch `stop()` retires, not the
        # cancellation it then issues. On 3.10 — the floor `ruff.toml` declares
        # — `asyncio.wait_for` discards a `CancelledError` that arrives after
        # the coroutine it wraps has already finished, so the cancel sent into
        # a refresh below can be swallowed whole: `_fetch`'s `except Exception`
        # would turn it into a routine `unreachable`, the loop would carry on
        # refreshing as fast as it could, and `stop()` — having spent its one
        # `task.cancel()` — would wait on it for ever. Reading the epoch makes
        # termination a fact about this object rather than about the
        # interpreter's cancellation semantics, on either version.
        while epoch == self._epoch:
            await self._sleep(self._interval)
            try:
                await self.refresh()
            except Exception:
                # `_refresh_once` turns every expected failure into an outcome,
                # so reaching here means something unforeseen. Logging and
                # continuing is right either way: a loop that dies leaves the
                # gateway enforcing whatever it last held, for ever, with
                # nothing after the traceback saying so.
                logger.exception("policy bundle refresh raised; the loop continues")

    async def _refresh_once(self) -> RefreshOutcome:
        held = self._held.version if self._held else None

        try:
            body = await self._fetch()
        except _Unreachable as failure:
            return self._unreachable(failure.reason, held)

        # `version` is a content hash, so an unchanged one means there is
        # nothing to re-parse — what is held is byte-for-byte what arrived. Read
        # off the raw body before validation, so the cheap path stays cheap.
        if isinstance(body, dict) and held is not None and body.get("version") == held:
            return RefreshOutcome("unchanged", held)

        try:
            bundle = validate_bundle(body)
        except UnusableBundle as refusal:
            # A fault to surface, not to route around: Rail Center and this
            # gateway have drifted, and the message naming the offending policy
            # is the only thing that fixes it.
            logger.error(
                "refusing the fetched policy bundle — %s; %s",
                refusal.reason,
                f"keeping version {safe_for_log(held)}" if held else "no bundle held",
            )
            return RefreshOutcome("unusable", held, refusal.reason)

        # `rejected` is not an error channel to drop. It names the policies Rail
        # Center could not compile, so a gateway that swallows it enforces a
        # chain narrower than the operator wrote with nothing on either side
        # saying so. One line per policy, every time the bundle changes — not
        # once at startup, since the set moves with the bundle.
        for entry in bundle.rejected:
            fields = entry if isinstance(entry, dict) else {}
            logger.warning(
                'Rail Center did not publish policy "%s" (%s): %s — it is not in force',
                safe_for_log(fields.get("policy_name")),
                safe_for_log(fields.get("policy_id")),
                safe_for_log(fields.get("reason")),
            )

        self._held = bundle
        logger.info(
            "holding policy bundle version %s — %d enabled policies, "
            "%d bound endpoints, %d rejected",
            safe_for_log(bundle.version),
            len(bundle.chain),
            len(bundle.bindings),
            len(bundle.rejected),
        )
        return RefreshOutcome("replaced", bundle.version)

    async def _fetch(self) -> Any:
        """The parsed body, or `_Unreachable` for every way of not getting one."""
        try:
            # Bounded, because the client's own timeout is httpx's and httpx
            # applies it per socket read: the timer restarts on every byte that
            # arrives, so it bounds a silence and not an attempt. This bounds
            # the attempt, and with it the lock `refresh()` is holding while it
            # runs.
            #
            # `wait_for` rather than an `asyncio.timeout` block, which reads
            # better and arrived in 3.11: `ruff.toml` declares 3.10 as the
            # lowest interpreter this project supports, and there the attribute
            # does not exist at all. The `except Exception` below would turn
            # that `AttributeError` into an ordinary `unreachable` on every
            # attempt — a gateway that never holds a bundle, forwards every
            # request unjudged, and reports itself unready for the life of the
            # process, while the log blames a control plane that is answering
            # perfectly well. Ruff's target version gates syntax, not stdlib
            # attributes, and CI runs one interpreter, so nothing else here
            # would catch it.
            #
            # What it costs on 3.10 is that a cancellation arriving after
            # `_attempt` has already completed is discarded rather than
            # propagated. `_loop` therefore ends on the epoch rather than on the
            # cancel, so a shutdown does not depend on which interpreter this
            # line is running under.
            return await asyncio.wait_for(self._attempt(), self._deadline)
        except _Unreachable:
            raise
        except asyncio.TimeoutError as error:
            # The deadline, not the socket: `str(TimeoutError())` is empty, so
            # the generic branch below would log the fault without naming it.
            # Spelled `asyncio.TimeoutError` because that is only the builtin
            # from 3.11 on; on 3.10 it is a separate class, and catching the
            # builtin there would leave the deadline unnamed.
            raise _Unreachable(
                f"policy bundle fetch ran past {self._deadline} seconds"
            ) from error
        except Exception as error:
            # `httpx` raises a family for connection, timeout, protocol and
            # decode failures, and `json.loads` raises its own. They differ in
            # cause and not in consequence: nothing usable arrived, so the last
            # bundle held stays in force. The type is named so the log line is
            # worth reading.
            raise _Unreachable(f"{type(error).__name__}: {error}") from error

    async def _attempt(self) -> Any:
        """One request and its body. Unbounded in time — `_fetch` bounds that."""
        # Streamed, so that the bound below bounds memory rather than only the
        # verdict. A non-streaming `get()` reads the whole body before it
        # returns, which would leave a responder free to commit whatever it can
        # send inside the deadline no matter what `max_bytes` says afterwards.
        async with (
            httpx.AsyncClient(
                timeout=self._timeout,
                transport=self._transport,
                # `RAIL_CENTER_URL` is the whole of where this call may go.
                # Left at its default, httpx reads `HTTP_PROXY` and `ALL_PROXY`
                # out of the process environment, so whatever can set a variable
                # in this container — a base image, a sidecar, an orchestrator —
                # chooses the host that answers with the ruleset this gateway
                # then enforces, and against an `http://` control plane sees the
                # bearer token on the way past.
                trust_env=False,
            ) as client,
            client.stream("GET", self._url, headers=self._headers) as response,
        ):
            if response.status_code in (401, 403):
                # The credential was produced and Rail Center refused it. Every
                # later refresh fails the same way until the configuration
                # changes, so name it distinctly from a control plane having a
                # bad minute.
                raise _Unreachable(
                    f"Rail Center rejected the credential ({response.status_code}); "
                    "every refresh fails this way until RAIL_AUTH_MODE and its "
                    "token are fixed"
                )
            if response.status_code >= 400:
                raise _Unreachable(f"Rail Center responded {response.status_code}")

            # The status and the headers arrive before the body, so a declared
            # length past the bound is refused without reading anything at all.
            # The header is the responder's claim though, and a responder that
            # under-declares or sends no length is bounded by the running total
            # below, which stops reading the moment it is past.
            declared = response.headers.get("content-length")
            if (
                declared is not None
                and declared.isdigit()
                and int(declared) > self._max_bytes
            ):
                raise _Unreachable(
                    f"policy bundle declares {declared} bytes, "
                    f"past the {self._max_bytes} this gateway reads"
                )

            # Decoded here, and taken off the response so that httpx does not
            # decode it first. Left to httpx, a running total bounds what is
            # *accumulated* and not what one chunk costs: each socket read is
            # expanded by whatever ratio the responder chose and handed over
            # already whole, so a body an eighth of the bound on the wire
            # allocates hundreds of megabytes inside a fetch this file believes
            # it has bounded at four. Decoded here, the wire is bounded on the
            # way in and the decoder is held to a `max_length`, so neither side
            # of the encoding can commit more than the bound.
            encoding = response.headers.pop("content-encoding", "").strip().lower()
            if encoding in ("", "identity"):
                decoder = None
            elif encoding == "gzip":
                decoder = zlib.decompressobj(_GZIP_WINDOW)
            else:
                raise _Unreachable(
                    f"policy bundle is {safe_for_log(encoding)}-encoded, which "
                    f"this gateway did not offer to read ({_ACCEPT_ENCODING})"
                )

            chunks: list[bytes] = []
            read = 0
            decoded = 0
            async for chunk in response.aiter_bytes():
                read += len(chunk)
                if read > self._max_bytes:
                    raise _Unreachable(
                        "policy bundle is past the "
                        f"{self._max_bytes} bytes this gateway reads"
                    )
                if decoder is not None:
                    # One byte past the budget is enough to know it is past it,
                    # and is all that is allocated: the rest stays in the
                    # decompressor's tail, which nothing here ever asks for.
                    chunk = decoder.decompress(chunk, self._max_bytes - decoded + 1)
                decoded += len(chunk)
                if decoded > self._max_bytes:
                    raise _Unreachable(
                        "policy bundle decodes past the "
                        f"{self._max_bytes} bytes this gateway reads"
                    )
                chunks.append(chunk)
            # `parse_constant` refuses `NaN`, `Infinity` and `-Infinity`, which
            # Python's `json` accepts by default and the reference
            # implementation's `JSON.parse` throws on. None of the three is
            # JSON, and a policy operand carrying one is a shape the contract
            # names outright: a `NaN` satisfies neither `lt 40` nor `gte 40`, so
            # it escapes a threshold rule from both directions while every type
            # check calls it a number. `gateway.ticket` refuses them at the
            # other door for the same reason.
            #
            # This is **not** the rule about an operand that *overflows* to
            # infinity. `1e400` is valid JSON, reads as `inf` on both sides, and
            # is evaluated rather than refused; the literal `Infinity` is a
            # different token and is not JSON at all.
            return json.loads(
                b"".join(chunks), parse_constant=_reject_non_json_constant
            )

    def _unreachable(self, reason: str, held: str | None) -> RefreshOutcome:
        # Both halves are filtered, and both need to be. `held` is a version off
        # the wire and reaches here on every failure for as long as it is held.
        # A reason built from an exception carries whatever the exception
        # carries: h11 quotes the bytes it could not parse — `illegal header
        # line: b'...'` — so a malformed response puts its own content in this
        # line. Python's own JSON decoder does not, reporting a line and column
        # instead.
        #
        # A warning while a bundle is held — the gateway is judging against a
        # ruleset that is merely not fresh. An error once nothing is held,
        # which is the more serious state.
        #
        # **Neither line says what becomes of traffic, and that is the point.**
        # The holder is constructed without a mode, so it cannot know: under
        # `enforce` a gateway holding no bundle refuses every request, under
        # `observe` it forwards every request unjudged, and those are as far
        # apart as an operator's log can put them. `_judge` writes that
        # sentence per request, where the mode is in hand. A claim made here
        # would be wrong for half the deployments that read it, and `enforce`
        # is the default half.
        safe = safe_for_log(reason)
        if held:
            logger.warning(
                "policy bundle fetch failed — %s; keeping version %s",
                safe,
                safe_for_log(held),
            )
        else:
            logger.error(
                "policy bundle fetch failed — %s; no bundle held",
                safe,
            )
        return RefreshOutcome("unreachable", held, safe)


class _Unreachable(Exception):
    """Internal: nothing usable arrived. Carries the reason and nothing else."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason
