"""Judge one call against the held bundle, and report the denials.

Every interface reads the request its own way and answers in its own way;
what a call's verdict is, what the refusal says and what Rail Center is told
are the same in all of them, so they live here.
"""

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Any

import httpx

from gateway.core.bundle.client import BundleHolder
from gateway.core.bundle.conditions import ConditionInput, UninterpretableCondition
from gateway.core.bundle.decide import decide, refuses_unbound
from gateway.core.bundle.validate import Policy, UsableBundle
from gateway.core.denial import build_report, report
from gateway.core.endpoint import EndpointResolution, resolve_from_body
from gateway.core.key_safety import safe_for_log
from gateway.core.mode import blocks, judges
from gateway.core.ticket import ParseResult, parse_rail_header

log = logging.getLogger(__name__)

#: The most denial reports this gateway will hold in flight at once, past which
#: a report is shed with a log rather than queued. The fallback refusal is
#: reached without a ticket, without a valid tool name and without any binding
#: existing, so anything that can reach this gateway can turn its own request
#: rate into one bearer-authenticated POST to Rail Center per request. Shedding
#: costs the record and not the enforcement — nothing the 403 is built from is
#: read back out of a report — while a gateway that has run out of sockets
#: reports nothing at all and stops refusing too.
MAX_REPORTS_IN_FLIGHT = 64

#: How much of that budget a report naming no policy may hold. The fallback
#: refusal is the class reachable with nothing in hand, so sharing one budget
#: first-come lets it evict the class that carries a verdict: a full set holds
#: every rule-decided denial off Rail Center's record for as long as it stays
#: full, and one slow Rail Center does the same with no caller meaning to.
#: Reserving the remainder is a comparison and a count, where making room by
#: cancelling a POST already in flight is neither.
MAX_FALLBACK_REPORTS_IN_FLIGHT = 16


@dataclass(frozen=True)
class Denial:
    """What a denial report is built from. `policy` is None for the fallback."""

    resolution: EndpointResolution
    ticket: ParseResult
    policy: Policy | None
    bundle: UsableBundle
    #: Every `x-rail-status` value the caller sent, unread.
    claimed_status: list[str] | None


@dataclass(frozen=True)
class Verdict:
    """Pass the call where `status` is None; otherwise refuse it with `status`
    and `reason`, and send `report` if there is one."""

    status: int | None = None
    reason: str = ""
    report: Denial | None = None


PASS = Verdict()


def judge(
    holder: BundleHolder,
    path: str,
    body: bytes,
    x_rail: list[str] | None,
    claimed_status: list[str] | None,
) -> Verdict:
    """What to do with one call: `body` as received, `path` as the upstream
    serves it, and every `x-rail` and `x-rail-status` value the caller sent.

    Never raises. A defect in the walk must not take the forward path down:
    an unforeseen exception is logged with its traceback and the request
    proceeds — a gateway that forwards nothing is worse than one that enforces
    nothing.
    """
    resolution = resolve_from_body(body, path)
    named = safe_for_log(resolution.key or resolution.status)
    if resolution.status == "discovery":
        # Not a call: it opens the session or lists what the session
        # offers, and the ticket it carries is judged on the first
        # `tools/call` instead. Passed ahead of the bundle check below too,
        # which costs nothing now that holding no bundle forwards anyway —
        # but keeps the two reasons distinct in the log, since a session
        # message was never going to be judged and a `tools/call` in that
        # window was.
        log.info("pass %s (session message, not judged)", named)
        return PASS
    ticket = parse_rail_header(x_rail)

    bundle = holder.current()
    if bundle is None:
        # **Forwarded, not refused** (RC-312). Holding no bundle used to be
        # read against a posture fixed at start-up, and `enforce` refused
        # every call. The posture now arrives *in* the bundle, so a gateway
        # holding none has not been told to enforce — it has been told
        # nothing, and refusing traffic on a ruleset nobody sent is enforcing
        # a decision no operator made. What keeps traffic off a gateway in
        # this state is `/ready`, which answers 503 until a bundle is held;
        # where nothing honours readiness the window is real, and the
        # contract says so rather than closing it here.
        log.error(
            "no policy bundle held — %s went unjudged and was forwarded; "
            "this gateway has been told no posture yet",
            named,
        )
        return PASS

    # Read here rather than at start-up, which is the whole of RC-312 on this
    # side: an operator moving a gateway to `none` during an incident, and
    # back afterwards, is two polls rather than two redeploys.
    if not judges(bundle.enforcement):
        log.info("pass %s (enforcement=none, judged nothing)", named)
        return PASS
    blocking = blocks(bundle.enforcement)

    # **Asked instead of the walk, wherever the chain would be walked.**
    # `block` refuses a call no binding matched without the chain being
    # consulted at all — but the *asking* happens at `observe` too, and only
    # the acting is held back to `enforce`. An operator has to be able to
    # see what `block` would refuse before it refuses anything, which is the
    # whole of what `observe` is for; a fallback silent until the day it
    # blocks makes the rung that exists to preview enforcement the one rung
    # that previews none of it.
    # **One reading, asked twice.** `resolution.key` is None for both keyless
    # outcomes and only one of them earns the narrowing: a message that
    # names no tool by design has no subject for an endpoint-derived rule,
    # while an `unrecognised` `tools/call` named one this gateway declined
    # to compose a key for and faces the whole chain. The fallback draws the
    # same line for the same reason, so the two read one value rather than
    # two spellings of it that can drift apart.
    keyless = resolution.status == "keyless"

    unbound = refuses_unbound(bundle, resolution.key, keyless=keyless)
    if unbound and not blocking:
        # **Said, and then not acted on — which is the whole distinction.**
        # Returning here would *act* on the fallback: at `enforce` a `block`
        # refuses without the chain being consulted, so short-circuiting
        # would make this mode enforce the one verdict it is supposed only
        # to preview. The walk below still runs, so an operator sees both
        # what the fallback would do and what the chain says about the same
        # call.
        log.warning(
            "would deny %s (no binding entry, fallback=block; ticket %s) — "
            "this mode enforces nothing, so it was forwarded",
            named,
            ticket.state,
        )
    if unbound and blocking:
        log.warning(
            "denied %s (no binding entry, fallback=block; ticket %s); "
            "no policy judged it",
            named,
            ticket.state,
        )
        # **Reported as an ordinary denial carrying no policy.** A refusal
        # nobody hears about is a refusal an operator debugs from the
        # caller's side: the fallback is the one verdict reached without a
        # rule, and leaving it unreported would make the endpoints nobody
        # bound the only ones whose refusals never appear.
        #
        # **The caller is told what any denied caller is told.** A distinct
        # status or reason here would let anyone holding a tool name probe
        # which endpoints this gateway has bindings for, one call at a
        # time — the same leak the policy id is withheld to prevent, and a
        # more useful one, because the answer is a map of the tenant's
        # coverage rather than a single rule.
        return Verdict(
            403,
            "denied by policy",
            Denial(resolution, ticket, None, bundle, claimed_status),
        )

    try:
        decision = decide(
            bundle,
            ConditionInput(ticket=ticket, endpoint_key=resolution.key),
            keyless=keyless,
        )
    except UninterpretableCondition as refusal:
        # The policy is named because disabling it is the remedy the
        # contract states, and an operator holding two rules with the same
        # unreadable condition cannot act on the field name alone.
        log.error(
            "refusing to judge %s — policy %s: %s; Rail Center and this "
            "gateway have drifted",
            named,
            safe_for_log(refusal.policy_id),
            refusal.reason,
        )
        return Verdict(503, "policy ruleset cannot be applied") if blocking else PASS
    except Exception:
        log.exception("policy evaluation raised for %s; forwarding", named)
        return PASS

    for alert in decision.alerts:
        log.warning("policy %s alerts on %s", safe_for_log(alert.id), named)

    if decision.allowed:
        log.info("allow %s (ticket %s)", named, ticket.state)
        return PASS

    # `denied_by` is the policy that **matched**. Reporting the chain's first
    # rule instead produces a record that is wrong and that nothing
    # downstream will contradict: Rail Center records this attribution and
    # does not re-derive it.
    policy = decision.denied_by
    if policy is None:  # pragma: no cover - `allowed` is False iff this is set
        log.error("denied %s with no policy named; forwarding", named)
        return PASS

    if not blocking:
        log.warning(
            "would deny %s by policy %s (ticket %s) — this mode enforces "
            "nothing, so the request was forwarded",
            named,
            safe_for_log(policy.id),
            ticket.state,
        )
        return PASS

    log.warning(
        "denied %s by policy %s (ticket %s)",
        named,
        safe_for_log(policy.id),
        ticket.state,
    )
    # **The policy id does not go back to the caller.** The `x-rail` ticket
    # is unsigned and this gateway is the only thing in front of the
    # upstream, so a caller that reads which id stopped each attempt can
    # vary its claims and binary-search the tenant's chain and its
    # thresholds. The operator's side of that trade is paid twice already —
    # the log line above names the policy, and so does the report to Rail
    # Center — both on the trusted side of the boundary.
    return Verdict(
        403,
        "denied by policy",
        Denial(resolution, ticket, policy, bundle, claimed_status),
    )


def refusal_body(reason: str) -> bytes:
    """The body every interface answers a refusal with."""
    return json.dumps({"error": reason}).encode()


class DenialReporter:
    """Sends denial reports to Rail Center, within the in-flight budgets."""

    def __init__(
        self,
        rail_center_url: str,
        auth: dict[str, str],
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._rail_center_url = rail_center_url
        self._auth = auth
        self._transport = transport
        # Strong references to the reports still in flight. A bare `create_task`
        # is only weakly held by the loop, so a report can be collected
        # mid-flight and simply never arrive — a missing row with nothing in the
        # log to say why.
        self._reports: set[asyncio.Task[Any]] = set()
        # The subset of those carrying no policy id — the fallback refusal,
        # which is the class reachable without a ticket, a tool name or a
        # binding. Counted apart from the whole so that class cannot spend the
        # budget the class carrying a verdict needs.
        self._unruled_reports: set[asyncio.Task[Any]] = set()

    def send(self, denial: Denial) -> None:
        """Report the denial without the caller waiting for it.

        Fire-and-forget: the caller has already been refused, so awaiting this
        would put Rail Center's availability into how long a denied request
        takes, and a failed report would look like a failed refusal.

        `policy` is None for a fallback refusal — the one verdict reached
        without a rule — and the report carries no `policy_id` rather than
        inventing one.

        **The key reported is the fullest one this gateway holds.** Where a
        binding matched, that is the key Rail Center published, slug and all,
        taken off the binding rather than recomposed; where none did, it is the
        slug-less form this gateway composed, which is all there is. The
        receiver resolves the data source from the reporting gateway and
        whichever it gets.

        **The budget is reserved by class.** A fallback refusal is reachable
        with nothing in hand — no ticket, no tool name, no binding — while a
        denial naming a policy took a rule that matched, so one shared budget
        makes the first class an eviction lever over the second: fill it with
        arbitrary bytes and every rule-decided denial is shed. A Rail Center
        slow enough to hold the tasks open reaches the same state with nobody
        meaning to. The policy-less class is held to
        `MAX_FALLBACK_REPORTS_IN_FLIGHT` of the `MAX_REPORTS_IN_FLIGHT` total,
        so the remainder is headroom a denial that names a rule always has.
        """
        policy = denial.policy
        unruled = policy is None
        if len(self._reports) >= MAX_REPORTS_IN_FLIGHT or (
            unruled and len(self._unruled_reports) >= MAX_FALLBACK_REPORTS_IN_FLIGHT
        ):
            log.warning(
                "denial report not sent — %d already in flight, %d of them "
                "naming no policy; this refusal stands and is absent from "
                "Rail Center",
                len(self._reports),
                len(self._unruled_reports),
            )
            return
        claims = denial.ticket.token or {}
        body = build_report(
            policy_id=policy.id if policy is not None else None,
            endpoint_key=_reportable_key(denial.bundle, denial.resolution.key),
            endpoint_status=denial.resolution.status,
            ticket_state=denial.ticket.state,
            agent_id=claims.get("agent_id"),
            posture_score=claims.get("posture_score"),
            claimed_status=_claimed_status(denial.claimed_status),
        )
        task = asyncio.create_task(
            report(self._rail_center_url, body, self._auth, transport=self._transport)
        )
        self._reports.add(task)
        task.add_done_callback(self._reports.discard)
        if unruled:
            self._unruled_reports.add(task)
            task.add_done_callback(self._unruled_reports.discard)


def _reportable_key(bundle, composed: str | None) -> str | None:
    """The full key where a binding matched, the composed one where none did.

    Reporting the binding's own key rather than the one this gateway composed
    hands the receiver an attribution it would otherwise re-derive: the whole
    key is the contract's, names one endpoint unambiguously, and arrived in the
    bundle rather than being guessed at here.

    **What it cannot promise is that the slug names the upstream the call
    reached.** The lookup is by the composed key, which has no data source in
    it — so where two upstreams behind this gateway share a stripped key and
    only one of them is bound, a call to either is reported under that one
    binding's slug. That is this implementation's stripped-key limitation
    showing up in the report rather than in the verdict, and it is the same
    limitation `bundle.validate` states at the collision refusal. A gateway
    resolving the data source from the route would match on the whole key and
    have neither face of it.

    Reporting the slug-less form instead is the alternative, and it is worse:
    it would lose an attribution that is correct in every case but this one.
    """
    if bundle is None or composed is None:
        return composed
    binding = bundle.bindings.get(composed)
    return binding.full_key if binding is not None else composed


def _claimed_status(values: list[str] | None) -> str | None:
    """What the caller said about why it sent no ticket, if it said anything.

    Recorded, never believed, and never near the field an operator reads as the
    verdict. A repeated header is dropped the way a repeated ticket is refused:
    two claims are not a claim.

    **Rendered through `safe_for_log`, because this is the last place a bound
    can be applied.** The value is a caller-chosen header that travels into a
    denial report's `metadata`, which Rail Center bounds only for the two keys
    it lifts out and otherwise stores free-form with no request-size limit in
    front of it. The caller chooses when a denial happens — send no ticket — so
    an unbounded write is on demand, and the vocabulary this header carries is
    three short words: past `MAX_LOGGED_LENGTH` the value is a payload rather
    than a claim, and a control character in it is a forgery aimed at whatever
    renders the row.
    """
    return safe_for_log(values[0]) if values and len(values) == 1 else None
