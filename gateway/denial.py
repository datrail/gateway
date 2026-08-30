"""Report a denial to Rail Center, and never let the report change the answer.

The contract puts two obligations on the reporting side, and both are about
attribution rather than delivery:

> **Report the policy that actually decided.** That id travels to an operator's
> screen as the rule which denied a call, with no second opinion standing behind
> it. An implementation that reports the first rule in its chain rather than the
> one that matched — or a rule it was configured with rather than one it
> evaluated — produces a record that is wrong and that nothing downstream will
> contradict.

> **A refusal is not a denial.** A policy named in a denial report must be a
> policy that was applied, because naming one is the only thing that makes it so.

Rail Center records the attribution and does not re-derive it: every denial it
serves carries ``policy_attribution: "reported"``, and the alert raised beside
one names the enforcement point as the source rather than asserting the verdict
as its own. So there is nothing downstream to catch a wrong id, and the second
obligation is why `report` is only ever called on a decision — never on a
refusal, where no policy decided anything.

**Fire-and-forget, and that is a decision rather than an optimisation.** The
caller has already been refused by the time this runs. Awaiting the report would
make Rail Center's availability a term in how long a denied request takes, and a
failure here would leave a request that *was* refused looking like one that
errored. What a failed report costs is a missing row, which the log line names.

**What the report carries, and what it must not.** `endpoint_key` — the resolved
key, the same value the walk took, never a raw path. The ticket does not travel:
the claims a condition read are not among the fields a report sends, so the
endpoint a call was refused against is on the record without the verdict being
reconstructable from it. And `metadata["x-rail-status"]` holds **this gateway's**
reading of the ticket under the exact key Rail Center reads. Anyone can set a
request header, so a caller's claimed status goes in beside it under a name that
says `claimed` and never into the field an operator reads as the decision.
"""

from __future__ import annotations

import logging
import math
import re
from datetime import datetime, timezone
from typing import Any

import httpx

from gateway.key_safety import safe_for_log

logger = logging.getLogger("gateway.denial")

#: The route is the OpenAPI specification's, as `/v1/policy-bundle` is.
DENIALS_PATH = "/v1/denials"

#: How long one report may take. Short, and bounded separately from the bundle
#: fetch: nothing waits on this, so a slow control plane should cost a dropped
#: row rather than a task that outlives the request it describes by a minute.
REPORT_TIMEOUT_SECONDS = 5.0

#: The metadata key Rail Center reads the enforcement point's verdict from —
#: `denials_router._REPORTED_STATUS_KEY`, matched exactly with no fallback. A
#: verdict reported under any other name leaves the operator-facing column
#: blank, so this string is a wire format rather than a label.
REPORTED_STATUS_KEY = "x-rail-status"

#: What the caller said about why it supplied no ticket. A proxy sends one of
#: `not-found`, `expired`, `issuer-unreachable`.
#:
#: **It proves nothing and identifies nobody.** The header is unauthenticated and
#: its vocabulary is public, so anyone reaching this gateway can send
#: `not-found` on a request that was going to be denied anyway and have it
#: recorded. It is a self-description that happens to be right in the ordinary
#: case, which is why the key says `claimed` and why it is nowhere near
#: `REPORTED_STATUS_KEY`.
#:
#: `expired` means something different in each: here the proxy is saying the
#: ticket it held lapsed so it sent none — which reads as `absent` in the
#: verdict — while in the verdict it means a ticket arrived and is past its
#: `exp`. Same word, opposite situations, which is why they never share a key.
CLAIMED_STATUS_KEY = "claimed-x-rail-status"


def _utc_now() -> str:
    """`denied_at`, as an absolute instant.

    A local-time value would shift every denial's timestamp by the host's UTC
    offset, and a denial's time is what an operator correlates against
    everything else they are looking at.
    """
    return datetime.now(timezone.utc).isoformat()


#: The canonical text form, 8-4-4-4-12. Hex in either case: pydantic folds it.
_CANONICAL = (
    "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

#: Every spelling `DenialEventRequest` accepts and no other: 32 undashed hex
#: digits, the canonical grouping, that grouping in braces, and that grouping
#: behind a lowercase `urn:uuid:`. Braces and the URN prefix take the canonical
#: form only — neither wraps the undashed one — and the prefix is matched
#: case-sensitively, both established by running the real model rather than
#: read off it. Unanchored, and matched with `fullmatch` at the one place it is
#: used, as `bundle.uuid` does for the same reason.
_READ_BY_RAIL_CENTER = re.compile(
    f"[0-9a-fA-F]{{32}}|{_CANONICAL}|\\{{{_CANONICAL}\\}}|urn:uuid:{_CANONICAL}"
)


def _reads_as_uuid(value: Any) -> bool:
    """Whether Rail Center will read `value` as the `uuid.UUID` it declares.

    A pattern, because **pydantic does not parse a UUID with `uuid.UUID`**, and
    that is the correction rather than a detail. This guard was first written as
    `uuid.UUID(value)` on the reasoning that running the schema's own function
    could not drift from the schema the way a hand-rolled pattern would — but it
    is not the schema's function, and the gap runs the wrong way. `uuid.UUID`
    strips every `-` before counting digits, so it reads
    `5c8f1e42000040008000-00000000a9e7`, a leading hyphen and a hyphen between
    every digit as one id where pydantic requires the grouping and 422s all
    three; it also accepts braces and `urn:uuid:` around the undashed form,
    which pydantic refuses. Each was a value this admitted and that route does
    not, which is the one property the guard exists to have.

    So the spellings above are established by validating each against the real
    `DenialEventRequest`, and that is how a change to them has to be checked —
    not by reasoning about what pydantic accepts, which is what went wrong.

    Deliberately not `bundle.uuid.canonical_uuid`: that one answers how this
    gateway compares two policy ids, and it is *wider* than this on purpose —
    the contract's five spellings must parse there or a bundle becomes an
    outage, while a spelling too wide here costs the denial. They disagree
    already, on braces around undashed hex, so sharing them would make a wire
    check move with an ordering tiebreak.

    Not shared with `posture_score`'s check either: that field is a number, and
    the two only look alike because both are claims off an unsigned ticket.
    """
    return isinstance(value, str) and _READ_BY_RAIL_CENTER.fullmatch(value) is not None


def _reads_as_number(value: Any) -> bool:
    """Whether Rail Center will read `value` as the `float` it declares.

    A bool before the numeric check, because `isinstance(True, int)` is true and
    a `posture_score` of `true` would otherwise be recorded as a score of 1.

    **Finite, and that is the whole of what this adds over a type check.** The
    ticket parser reads numbers with `parse_int=float` deliberately — its own
    comment has a long literal saturating "to infinity exactly as it does in the
    reference" — so `1e400`, `-1e400` and a 400-digit integer all arrive here as
    `inf`. httpx serialises the body with ``json.dumps(..., allow_nan=False)``,
    which raises on one, and `report` catches everything: the whole denial is
    lost rather than the one field. An integer too large to be a float is the
    same answer from the other side, `math.isfinite` raising where
    `DenialEventRequest` 422s, so it is refused here rather than crashing.

    The saturation itself stays where it is. The evaluation contract fixes what
    the parser does with a long literal, so the bound belongs on what this sends.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def build_report(
    *,
    policy_id: str,
    datasource_slug: str,
    endpoint_key: str | None,
    endpoint_status: str,
    ticket_state: str,
    agent_id: Any = None,
    posture_score: Any = None,
    claimed_status: str | None = None,
) -> dict[str, Any]:
    """The body of one denial report.

    `policy_id` is the policy that **matched**, which the caller is responsible
    for having taken from the decision rather than from the chain.

    `agent_id` and `posture_score` are passed through only when they are the
    shape Rail Center's schema declares — a UUID string and a finite number. The
    ticket is unsigned, so both are attacker-chosen: a claim of the wrong shape
    would be a 422 on the report, and on this route a 422 means the denial is
    not recorded at all. Dropping a malformed claim costs a column; sending it
    costs the row.
    """
    metadata: dict[str, Any] = {
        # Reported beside the key and never inside it, so a call that resolved
        # to nothing stays distinguishable from an endpoint with no rule.
        "endpoint_resolution": endpoint_status,
        # This gateway's reading, under the key Rail Center reads. All four
        # unusable ticket states fold into one decision, and an operator still
        # has to be able to tell an expired ticket — a correctly formed
        # credential that is simply too old — from one that could not be read.
        REPORTED_STATUS_KEY: ticket_state,
    }
    if claimed_status is not None:
        metadata[CLAIMED_STATUS_KEY] = claimed_status

    report: dict[str, Any] = {
        "policy_id": policy_id,
        # The slug rather than the row id: this gateway already holds the slug —
        # it is the segment it qualifies every endpoint key with — where an id
        # is a second value it would have to be told and could hold a stale copy
        # of. Exactly one of the two is required, and this is the one that costs
        # nothing.
        "datasource_slug": datasource_slug,
        "endpoint_key": endpoint_key,
        "denied_at": _utc_now(),
        "metadata": metadata,
    }
    if _reads_as_uuid(agent_id):
        report["agent_id"] = agent_id
    if _reads_as_number(posture_score):
        report["posture_score"] = posture_score
    return report


async def report(
    rail_center_url: str,
    body: dict[str, Any],
    headers: dict[str, str],
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> bool:
    """Send one denial report. Never raises; returns whether it was accepted.

    Every failure is swallowed and logged. The request this describes has
    already been refused, so nothing here can change what the caller sees, and
    an exception escaping would turn a recorded refusal into an unhandled error
    in whatever scheduled it.

    Rail Center answers 202 and de-duplicates ingested denials itself. It does
    that over the record it stores, not over the bytes it was sent, so what the
    identity covers — and which retries fall outside it — is the receiver's to
    state and is documented there. What this side owes it is a body that does not
    move between attempts: `denied_at` is part of that identity, so a report
    rebuilt per attempt carries a fresh timestamp and is a different record every
    time. Build the report once and resend that one.

    No `idempotency_key` is minted. The field overrides the receiver's own
    derivation and exists for two refusals that really are distinct and really
    are identical, which two refusals of ours never are.
    """
    url = rail_center_url.rstrip("/") + DENIALS_PATH
    try:
        async with httpx.AsyncClient(
            timeout=REPORT_TIMEOUT_SECONDS, transport=transport
        ) as client:
            response = await client.post(url, json=body, headers=headers)
    except Exception as exc:  # noqa: BLE001 - a report may not break a refusal
        logger.warning(
            "denial report for policy %s could not be sent: %s: %s",
            safe_for_log(body.get("policy_id")),
            type(exc).__name__,
            exc,
        )
        return False

    if response.status_code != 202:
        # Named rather than swallowed: a 422 here means this gateway and Rail
        # Center disagree about the shape of a denial, and the row is missing.
        logger.warning(
            "denial report for policy %s was refused: HTTP %d",
            safe_for_log(body.get("policy_id")),
            response.status_code,
        )
        return False
    return True
