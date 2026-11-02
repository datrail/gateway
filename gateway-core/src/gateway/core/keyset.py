"""The key set signed tickets are verified against, and how it stays current.

The rules are rail-center's `docs/policy-evaluation-contract.md`, "A signed
ticket". Keys come from one place only — `RAIL_CENTER_URL` + `/v1/jwks.json`,
fetched with this gateway's own credential, over HTTPS with the certificate
checked and no redirect followed — and are held only for the maximum key-set
age after the last fetch that succeeded. **Unlike the policy bundle, which is
kept however old it is, a key set is not**: that age is what makes withdrawing
a key reach a gateway that cannot reach Rail Center, so it is a security bound
and not a tuning knob.

Nothing here verifies a ticket. `verifier()` hands the reader what is held,
and `ensure()` reads only a signed header's `kid`, to decide whether a request
is worth one refetch first.
"""

import asyncio
import json
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from gateway.core.key_safety import safe_for_log
from gateway.core.ticket import TicketVerifier, signed_kid, usable_keys

log = logging.getLogger(__name__)

#: The route is the contract's, not a deployment's: what a deployment
#: configures is `RAIL_CENTER_URL`, and a key set from anywhere else is not one
#: this gateway holds.
JWKS_PATH = "/v1/jwks.json"

#: How often the set is refetched, in seconds: the contract's refresh interval.
#: Rail Center publishes a scheduled key at least this long before it starts
#: signing, so a gateway refreshing on time holds it before its first ticket.
#: A compromise withdrawal's replacement signs as it is published, and is the
#: case `KeySetHolder.ensure` refetches for.
REFRESH_SECONDS = 300

#: How long a set is held after the last fetch that succeeded, in seconds.
#: Three refresh intervals, so one or two late refreshes do not lock every
#: signed ticket out, and fixed rather than tied to the ticket lifetime, so a
#: longer lifetime does not widen how long a withdrawn key goes on verifying.
MAX_KEY_SET_AGE_SECONDS = 900

#: The least time between two refetches asked for by an unknown `kid`, in
#: seconds, so a stream of invented `kid`s cannot become a stream of fetches.
UNKNOWN_KID_REFETCH_SECONDS = 30

#: The deadline on one whole fetch, in seconds. A request naming an unknown
#: `kid` waits for at most this long for its own fetch, and at most this long
#: again first if a refresh is already in flight, after which it fetches only
#: when that refresh did not bring the key.
FETCH_DEADLINE_SECONDS = 10.0

#: The largest key set this gateway reads, in bytes. A tenant publishes a few
#: keys of under 200 bytes each; past this a body is a fault, not a big tenant.
MAX_JWKS_BYTES = 64 * 1024


def boottime_clock() -> tuple[Callable[[], float], bool]:
    """A clock for the key-set age, and whether it counts through suspend.

    `CLOCK_BOOTTIME` keeps counting while the host is suspended, which
    `CLOCK_MONOTONIC` does not: a gateway that slept through a withdrawal would
    otherwise wake still trusting the withdrawn key for however long the sleep
    lasted. Linux has it, and so does every container this ships in; elsewhere
    the monotonic clock stands in, and the caller says so at startup.
    """
    boottime = getattr(time, "CLOCK_BOOTTIME", None)
    if boottime is None:
        return time.monotonic, False
    return (lambda: time.clock_gettime(boottime)), True


@dataclass(frozen=True)
class KeySetOutcome:
    """What one fetch produced, for the log line and for a test.

    * ``replaced`` a usable set arrived and is now held
    * ``failed``   nothing usable arrived, and what was held stays held until it
      ages out
    """

    kind: Literal["replaced", "failed"]
    #: The `kid`s held afterwards, or an empty tuple when nothing is.
    kids: tuple[str, ...]
    #: Why, for a failed fetch. Already passed through `safe_for_log`.
    reason: str | None = None


class KeySetHolder:
    """Rail Center's key set for this gateway's tenant, and how it stays held."""

    def __init__(
        self,
        rail_center_url: str,
        headers: dict[str, str],
        *,
        issuer: str | None,
        audience: str | None,
        requires_signatures: bool = False,
        deadline_seconds: float = FETCH_DEADLINE_SECONDS,
        max_bytes: int = MAX_JWKS_BYTES,
        # Injected so the tests need neither a network, a wait nor a clock.
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._https = urlsplit(rail_center_url).scheme == "https"
        self._url = rail_center_url.rstrip("/") + JWKS_PATH
        self._headers = {
            "Accept": "application/json",
            **headers,
            # Last, so they are not the caller's to change. A cache between this
            # gateway and Rail Center handing back a set Rail Center has since
            # changed would restart the age on a key already withdrawn; and an
            # encoding this holder did not offer is one its bound cannot count.
            "Cache-Control": "no-cache",
            "Accept-Encoding": "identity",
        }
        self._issuer = issuer
        self._audience = audience
        self._requires_signatures = requires_signatures
        self._deadline = deadline_seconds
        self._max_bytes = max_bytes
        self._transport = transport
        self._sleep = sleep or asyncio.sleep
        self._clock = clock or boottime_clock()[0]

        self._keys: dict[str, Ed25519PublicKey] | None = None
        self._fetched_at: float | None = None
        self._lock = asyncio.Lock()
        self._forced: asyncio.Task[KeySetOutcome | None] | None = None
        self._forced_at: float | None = None
        self._task: asyncio.Task[None] | None = None
        self._epoch = 0

    @property
    def requires_signatures(self) -> bool:
        return self._requires_signatures

    def holds_keys(self) -> bool:
        """Whether a set is held that has not passed its maximum age."""
        return (
            self._keys is not None
            and self._fetched_at is not None
            and self._clock() - self._fetched_at <= MAX_KEY_SET_AGE_SECONDS
        )

    def verifier(self) -> TicketVerifier:
        """What a ticket read now is checked against.

        The age is judged here, at the moment of reading, and not by the loop:
        a loop that cleared the set on its own schedule would leave a set one
        tick past its age still verifying until the tick came round.
        """
        return TicketVerifier(
            keys=self._keys if self.holds_keys() else None,
            issuer=self._issuer,
            audience=self._audience,
            requires_signatures=self._requires_signatures,
        )

    async def ensure(self, value: str | list[str] | tuple[str, ...] | None) -> None:
        """Refetch first when `value` is a signed header naming a `kid` not held.

        The request waits, because the contract reads a `kid` the gateway holds
        no key for as `bad_signature` only "once it has refetched its keys": a
        key that signs at once — a compromise withdrawal's replacement — is
        published at the same moment, and its first tickets would otherwise be
        refused. At most one such refetch runs per `UNKNOWN_KID_REFETCH_SECONDS`,
        and callers arriving while it runs wait on that same fetch.

        **Nothing raises out of here.** Every way a fetch fails is already an
        outcome, so a raise is a defect, and it is logged rather than passed on:
        the Apigee callout forwards a request whose handler raises, so passing
        it on would admit a ticket no key was checked against, where the set
        still held reads it as `bad_signature`.
        """
        try:
            await self._ensure(value)
        except Exception:
            log.exception("the signing key set refetch raised; the set held is kept")

    async def _ensure(self, value: str | list[str] | tuple[str, ...] | None) -> None:
        kid = signed_kid(value)
        if kid is None:
            return
        if self.holds_keys() and kid in (self._keys or {}):
            return
        if self._forced is not None and not self._forced.done():
            await asyncio.shield(self._forced)
            return
        now = self._clock()
        if (
            self._forced_at is not None
            and now - self._forced_at < UNKNOWN_KID_REFETCH_SECONDS
        ):
            return
        self._forced_at = now
        self._forced = asyncio.create_task(self._refresh_for(kid))
        # Shielded, so a request cancelled while waiting does not take the fetch
        # other requests are waiting on with it.
        await asyncio.shield(self._forced)

    async def refresh(self) -> KeySetOutcome:
        """One fetch, whatever the outcome."""
        async with self._lock:
            return await self._refresh_once()

    async def _refresh_for(self, kid: str) -> KeySetOutcome | None:
        """A refetch for `kid`, unless a refresh that held the lock meanwhile
        has already brought it: fetching again would cost the request a second
        deadline for a set it already has. None when nothing was fetched."""
        async with self._lock:
            if self.holds_keys() and kid in (self._keys or {}):
                return None
            return await self._refresh_once()

    async def start(self) -> KeySetOutcome:
        """Fetch once, then keep refreshing in the background.

        Over a Rail Center that is not `https://` there is nothing to fetch and
        no loop to run: said once here, at warning level, since unsigned tickets
        still read as they always have and only signed ones are refused.
        """
        if not self._https:
            log.warning(
                "RAIL_CENTER_URL is not https://, so no signing key set is fetched "
                "and every signed ticket reads bad_signature"
            )
            return KeySetOutcome("failed", (), "RAIL_CENTER_URL is not https://")
        epoch = self._epoch
        outcome = await self.refresh()
        if epoch == self._epoch and (self._task is None or self._task.done()):
            self._task = asyncio.create_task(self._loop(epoch))
        return outcome

    async def stop(self) -> None:
        """Stop refreshing. Safe to call twice, and safe with a fetch in flight."""
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
        # Ended by the epoch `stop()` retires, as `BundleHolder._loop` is: a
        # cancel landing inside a fetch can be turned into a routine failure,
        # and the loop must still end.
        while epoch == self._epoch:
            await self._sleep(REFRESH_SECONDS)
            try:
                await self.refresh()
            except Exception:
                log.exception("key set refresh raised; the loop continues")

    async def _refresh_once(self) -> KeySetOutcome:
        if not self._https:
            # Refused before any request, and quietly: `start` has said it once.
            return KeySetOutcome("failed", (), "RAIL_CENTER_URL is not https://")
        try:
            body = await asyncio.wait_for(self._attempt(), self._deadline)
        except _Failed as failure:
            return self._failed(failure.reason)
        except TimeoutError:
            return self._failed(f"the fetch ran past {self._deadline} seconds")
        except Exception as error:  # noqa: BLE001 - every way of not getting a set
            # httpx raises a family for connection, protocol and decode failures.
            # They differ in cause and not in consequence: nothing usable arrived,
            # so what is held stays held until it ages out. The type is named so
            # the line is worth reading.
            return self._failed(f"{type(error).__name__}: {error}")

        keys = usable_keys(body)
        if keys is None:
            return self._failed(
                "the set holds no usable Ed25519 key, or two entries share a kid"
            )
        previous = set(self._keys or {}) if self.holds_keys() else None
        self._keys = keys
        self._fetched_at = self._clock()
        kids = tuple(sorted(keys))
        if previous != set(kids):
            # On the change, never on the poll: a set refetched every interval
            # mostly says what the last one said.
            log.info(
                "holding signing keys %s", ", ".join(safe_for_log(k) for k in kids)
            )
        return KeySetOutcome("replaced", kids)

    async def _attempt(self) -> Any:
        async with (
            httpx.AsyncClient(
                timeout=self._deadline,
                transport=self._transport,
                # `RAIL_CENTER_URL` is the whole of where this call may go: a
                # proxy variable in the environment would choose the host that
                # answers with the keys this gateway trusts.
                trust_env=False,
                follow_redirects=False,
            ) as client,
            client.stream("GET", self._url, headers=self._headers) as response,
        ):
            if response.status_code in (401, 403):
                raise _Failed(
                    f"Rail Center rejected the credential ({response.status_code})"
                )
            if response.status_code != 200:
                raise _Failed(f"Rail Center responded {response.status_code}")
            encoding = response.headers.get("content-encoding", "").strip().lower()
            if encoding not in ("", "identity"):
                raise _Failed(f"the set is {safe_for_log(encoding)}-encoded")
            declared = response.headers.get("content-length")
            if (
                declared is not None
                and declared.isdigit()
                and int(declared) > self._max_bytes
            ):
                raise _Failed(
                    f"the set declares {declared} bytes, past {self._max_bytes}"
                )
            read = bytearray()
            # `aiter_bytes`, not `aiter_raw`: with every encoding but identity
            # refused above, the two yield the same bytes, and only this one
            # also reads a body httpx has already buffered.
            async for chunk in response.aiter_bytes():
                read += chunk
                if len(read) > self._max_bytes:
                    raise _Failed(f"the set is past {self._max_bytes} bytes")
            try:
                # `parse_constant` refuses `NaN`, `Infinity` and `-Infinity`,
                # which Python's `json` accepts and a reader on another runtime
                # does not: the bundle fetch and the ticket reader refuse them at
                # their doors for the same reason, and a key set is a third.
                return json.loads(bytes(read), parse_constant=_reject_non_json_constant)
            except ValueError as error:
                raise _Failed(f"the set is not JSON: {error}") from None

    def _failed(self, reason: str) -> KeySetOutcome:
        safe = safe_for_log(reason)
        held = self.holds_keys()
        if held:
            log.warning("signing key fetch failed — %s; keeping the set held", safe)
        else:
            # An error once nothing is held: every signed ticket now reads
            # bad_signature until a fetch succeeds.
            log.error(
                "signing key fetch failed — %s; no key set held, so every signed "
                "ticket reads bad_signature",
                safe,
            )
        return KeySetOutcome(
            "failed", tuple(sorted(self._keys or {})) if held else (), safe
        )


def _reject_non_json_constant(name: str) -> Any:
    """Refuse `NaN`, `Infinity` and `-Infinity`: none of them is JSON."""
    raise ValueError(f"{name} is not JSON")


class _Failed(Exception):
    """Internal: nothing usable arrived. Carries the reason and nothing else."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason
