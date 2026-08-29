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
hold nothing and let the caller refuse.

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

#: The deadline on one fetch. Five seconds is far more than a same-region round
#: trip, and short enough that a control plane which has stopped answering
#: without closing the connection costs one refresh rather than an unbounded
#: wait.
#:
#: Attempts do not pile up without it: `_loop` awaits the sleep and the refresh
#: in sequence, and `refresh()` serialises on a lock. What the deadline bounds is
#: how long a hung fetch holds that lock — which is what the next scheduled
#: refresh, and any manual one, waits behind.
FETCH_TIMEOUT_SECONDS = 5.0

#: The largest bundle this gateway will read, in bytes.
#:
#: The deadline bounds how *long* a response may take and says nothing about how
#: *large* it may be: a control plane answering quickly with an enormous body
#: would otherwise be read whole. Four megabytes is far more than a tenant's
#: whole ruleset — a chain is a few dozen policies of a few hundred bytes — and
#: small enough that a body past it is a fault rather than a big customer. One
#: past it is treated as unreachable, so the last bundle held stays in force.
MAX_BUNDLE_BYTES = 4 * 1024 * 1024

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
        max_bytes: int = MAX_BUNDLE_BYTES,
        # Injected so the tests need neither a network nor a wait. A caller that
        # passes neither gets the real ones.
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        self._url = rail_center_url.rstrip("/") + BUNDLE_PATH
        self._headers = _sendable({"Accept": "application/json", **headers})
        self._interval = interval_seconds
        self._timeout = timeout_seconds
        self._max_bytes = max_bytes
        self._transport = transport
        self._sleep = sleep or asyncio.sleep

        self._held: UsableBundle | None = None
        self._task: asyncio.Task[None] | None = None
        self._lock = asyncio.Lock()

    def current(self) -> UsableBundle | None:
        """The bundle to decide against, or **None when none was ever held**.

        Never a bundle that failed validation, and never cleared by a failed
        fetch: the last usable bundle stays until a newer usable one replaces
        it. A caller reading None refuses traffic — that is the whole of what
        None means, and it is not the same as a bundle with no policies, which
        allows.
        """
        return self._held

    async def refresh(self) -> RefreshOutcome:
        """One attempt, whatever the outcome.

        Serialised on a lock rather than coalesced into a shared future: a
        caller asking for a refresh wants a fresh answer, and handing it the
        result of an attempt that started before it asked is a subtly different
        promise. The cost is that a manual refresh waits behind a scheduled one,
        which is bounded by the timeout.
        """
        async with self._lock:
            return await self._refresh_once()

    async def start(self) -> RefreshOutcome:
        """Fetch once, then keep refreshing in the background.

        Returns after the first attempt whether or not it succeeded. A gateway
        holding no bundle still starts and still listens — it just refuses every
        request while the loop keeps trying, which is a state an operator can
        see and act on. Refusing to start would turn a control plane that is
        briefly down into a gateway that never comes up.

        Calling it twice refreshes twice and still leaves one loop. Overwriting
        `_task` instead would drop the only handle to the first, which nothing
        could then cancel: it would keep refreshing for the life of the process,
        contending for the lock and doubling the load on the control plane.
        """
        outcome = await self.refresh()
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._loop())
        return outcome

    async def stop(self) -> None:
        """Stop refreshing. Safe to call twice, and safe with one in flight."""
        task, self._task = self._task, None
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    async def _loop(self) -> None:
        while True:
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
                f"keeping version {safe_for_log(held)}"
                if held
                else "no bundle held, refusing traffic",
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
            # Streamed, so that the bound below bounds memory rather than only
            # the verdict. A non-streaming `get()` reads the whole body before
            # it returns, which would leave a responder free to commit whatever
            # it can send inside the deadline no matter what `max_bytes` says
            # afterwards.
            async with (
                httpx.AsyncClient(
                    timeout=self._timeout,
                    transport=self._transport,
                    # `RAIL_CENTER_URL` is the whole of where this call may go.
                    # Left at its default, httpx reads `HTTP_PROXY` and
                    # `ALL_PROXY` out of the process environment, so whatever
                    # can set a variable in this container — a base image, a
                    # sidecar, an orchestrator — chooses the host that answers
                    # with the ruleset this gateway then enforces, and against
                    # an `http://` control plane sees the bearer token on the
                    # way past.
                    trust_env=False,
                ) as client,
                client.stream("GET", self._url, headers=self._headers) as response,
            ):
                if response.status_code in (401, 403):
                    # The credential was produced and Rail Center refused it.
                    # Every later refresh fails the same way until the
                    # configuration changes, so name it distinctly from a
                    # control plane having a bad minute.
                    raise _Unreachable(
                        f"Rail Center rejected the credential ({response.status_code}); "
                        "every refresh fails this way until RAIL_AUTH_MODE and its "
                        "token are fixed"
                    )
                if response.status_code >= 400:
                    raise _Unreachable(f"Rail Center responded {response.status_code}")

                # The status and the headers arrive before the body, so a
                # declared length past the bound is refused without reading
                # anything at all. The header is the responder's claim
                # though, and a responder that under-declares or sends no
                # length is bounded by the running total below, which stops
                # reading the moment it is past.
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

                chunks: list[bytes] = []
                read = 0
                async for chunk in response.aiter_bytes():
                    read += len(chunk)
                    if read > self._max_bytes:
                        raise _Unreachable(
                            "policy bundle is past the "
                            f"{self._max_bytes} bytes this gateway reads"
                        )
                    chunks.append(chunk)
                return json.loads(b"".join(chunks))
        except _Unreachable:
            raise
        except Exception as error:
            # `httpx` raises a family for connection, timeout, protocol and
            # decode failures, and `json.loads` raises its own. They differ in
            # cause and not in consequence: nothing usable arrived, so the last
            # bundle held stays in force. The type is named so the log line is
            # worth reading.
            raise _Unreachable(f"{type(error).__name__}: {error}") from error

    def _unreachable(self, reason: str, held: str | None) -> RefreshOutcome:
        # Both halves are filtered, and both need to be. `held` is a version off
        # the wire and reaches here on every failure for as long as it is held.
        # A reason built from an exception carries whatever the exception
        # carries: h11 quotes the bytes it could not parse — `illegal header
        # line: b'...'` — so a malformed response puts its own content in this
        # line. Python's own JSON decoder does not, reporting a line and column
        # instead.
        #
        # A warning while a bundle is held — the gateway is still enforcing,
        # against a ruleset that is merely not fresh. An error once nothing is
        # held, because every request is now refused.
        safe = safe_for_log(reason)
        if held:
            logger.warning(
                "policy bundle fetch failed — %s; keeping version %s",
                safe,
                safe_for_log(held),
            )
        else:
            logger.error(
                "policy bundle fetch failed — %s; no bundle held, refusing traffic",
                safe,
            )
        return RefreshOutcome("unreachable", held, safe)


class _Unreachable(Exception):
    """Internal: nothing usable arrived. Carries the reason and nothing else."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason
