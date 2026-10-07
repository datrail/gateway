"""Helpers for the gateway-core suite, and for the members built on gateway-core.

The root `pyproject.toml` puts this folder on `sys.path`, as it does each
member's own support module.
"""

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import pytest

from gateway.core.bundle.validate import UsableBundle, validate_bundle
from gateway.core.endpoint import MAX_BODY_NESTING_DEPTH
from gateway.core.key_safety import MAX_LOGGED_LENGTH

SLUG = "delivery"
KEY = "/mcp#tools/call#track_package"

DENY_ID = "5c8f1e42-0000-4000-8000-0000000000d1"
SKILL_ID = "5c8f1e42-0000-4000-8000-0000000000d2"
BAD_ID = "5c8f1e42-0000-4000-8000-0000000000e1"

#: The `agent_id` every ticket here carries unless a case says otherwise.
AGENT = "5c8f1e42-0000-4000-8000-00000000a9e7"


def policy(pid: str, condition: dict[str, Any], *, priority: int = 1, action="block"):
    return {
        "id": pid,
        "name": f"policy {pid[-2:]}",
        "priority": priority,
        "condition": condition,
        "action": action,
        "enabled": True,
    }


def bundle(
    *policies: dict[str, Any],
    bindings: list[dict[str, Any]] | None = None,
    enforcement: str = "enforce",
    fallback: str = "pass",
):
    """A validated bundle, at `enforce`/`pass` unless a case asks otherwise.

    The posture is part of the bundle after RC-312 rather than a flag on the
    layer that reads it, which is why it is a parameter here: a case that wants
    a verdict logged and not acted on asks for an `observe` bundle, the same way
    an operator would.

    **The fallback default is `pass` and Rail Center's is `block`**, which is a
    deliberate disagreement rather than an oversight. Almost every case here is
    about the walk — which policy denied, what the report names, what the caller
    is told — and every one of them calls an endpoint with no binding entry,
    because a binding is not what any of them is testing. Under `block` the
    fallback would refuse each of those before the chain was reached, and the
    file would pass while asserting nothing about the walk at all. The cases
    that *are* about the fallback name it.
    """
    return validate_bundle(
        {
            "schema_version": "1.0",
            "content_hash": "v-enforce",
            "policies": list(policies),
            "bindings": bindings or [],
            "enforcement": {"mode": enforcement},
            "binding_fallback": fallback,
        }
    )


#: The seeded "deny unknown agents": it holds on any request arriving without a
#: ticket, which is every request below that does not deliberately carry one.
#: One rule in the chain, so the policy a report names is never ambiguous.
DENIES_EVERYTHING = policy(DENY_ID, {"field": "x_rail_header", "operator": "missing"})

#: Denies a request that *does* carry a ticket, for the handful of cases whose
#: subject is what the claims on one become in a report. It keys on the presence
#: of `agent_id` rather than on the claim's value, so a test can send a malformed
#: claim and still reach the denial the malformed claim is about.
DENIES_ANY_TICKET = policy(DENY_ID, {"field": "agent_id", "operator": "present"})

#: Keyed on the endpoint, so it leaves the chain for a message that names no
#: tool by design and stays in it for one this gateway could not resolve.
DENIES_UNMATCHED_SKILL = policy(
    SKILL_ID, {"field": "skill_match", "operator": "missing"}
)

#: Outside the grammar. Two of these at different priorities is what asks
#: whether a refusal names the rule an operator has to disable.
UNREADABLE = {"field": "invented_field", "operator": "eq", "value": 1}

#: An alert on any ticket. It is in the chain so that a case can bind an
#: endpoint to something without that something denying — what is being asserted
#: is that the walk happened, not what it concluded.
NOTES_ANY_TICKET = policy(
    SKILL_ID, {"field": "agent_id", "operator": "present"}, action="alert"
)

#: `delivery#/mcp#tools/call#track_package`, gated to the one policy above. A
#: binding *entry* is what the fallback looks for; which policies it names is the
#: chain's business. A binding as the bundle carries it — the **full** key, with
#: the data source slug Rail Center composed it from. The gateway strips that
#: first segment and matches the rest against what it composed from the request,
#: so a fixture carrying the comparable form would pass while testing nothing
#: about the strip.
FULL_KEY = f"{SLUG}#{KEY}"
BOUND = {"endpoint_key": FULL_KEY, "mode": "gated", "policy_ids": [SKILL_ID]}


class Holder:
    """A bundle holder that holds what the test said, and nothing else.

    `judge` asks it one question — `current()` — so standing up a real
    `BundleHolder` and a control plane for it would be a fetch, a refresh loop
    and a transport in service of a single return value.
    """

    def __init__(self, held=None):
        self.held = held

    def current(self):
        return self.held


def ticket(**claims: Any) -> str:
    """An `x-rail` header carrying `claims`, unpadded as the mint emits it."""
    claims.setdefault("agent_id", AGENT)
    claims.setdefault("exp", 4102444800)  # 2100-01-01, comfortably unexpired
    raw = json.dumps(claims).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def call(tool: str = "track_package") -> bytes:
    return json.dumps({"method": "tools/call", "params": {"name": tool}}).encode()


KEYLESS = json.dumps({"method": "resources/read"}).encode()
DISCOVERY = tuple(
    json.dumps({"method": m}).encode()
    for m in ("initialize", "notifications/initialized", "tools/list")
)


def deep_call(depth: int) -> bytes:
    """A `tools/call` nesting `depth` levels — a kilobyte of brackets, no more."""
    inner = "[" * (depth - 3) + "]" * (depth - 3)
    return (
        '{"method": "tools/call", "params": {"name": "track_package", '
        f'"arguments": {{"q": {inner}}}}}}}'
    ).encode()


#: What each refusal tells the caller, spelled out rather than imported: the
#: body is the wire format.
REASONS = {403: "denied by policy", 503: "policy ruleset cannot be applied"}


def report(
    *,
    policy_id: str | None = DENY_ID,
    key: str | None = KEY,
    resolution: str = "resolved",
    ticket_state: str = "absent",
    claimed: str | None = None,
    **claims: Any,
) -> dict[str, Any]:
    """A denial report as Rail Center receives it, less `denied_at`.

    The keys are literals for the same reason as `REASONS`.
    """
    metadata = {"endpoint_resolution": resolution, "x-rail-status": ticket_state}
    if claimed is not None:
        metadata["claimed-x-rail-status"] = claimed
    return {
        **({"policy_id": policy_id} if policy_id is not None else {}),
        "endpoint_key": key,
        "metadata": metadata,
        **claims,
    }


@dataclass(frozen=True)
class EnforcementCase:
    """One row of the enforcement contract: a held bundle, one request, and
    what the caller and Rail Center get.

    Standalone's behaviour is the definition. An interface a row does not apply
    to names it in `not_for` with the reason, which `enforcement_params` turns
    into a visible skip.
    """

    name: str
    policies: tuple[dict[str, Any], ...] = ()
    bindings: tuple[dict[str, Any], ...] = ()
    #: The bundle's posture; None where no bundle is held.
    enforcement: str | None = "enforce"
    fallback: str = "pass"
    method: str = "POST"
    path: str = "/mcp"
    body: bytes = call()
    x_rail: tuple[str, ...] = ()
    x_rail_status: tuple[str, ...] = ()
    #: The refusal's status; None where the call is forwarded.
    status: int | None = None
    #: The denial report, as `report()` builds it; None where none is sent.
    report: Mapping[str, Any] | None = None
    not_for: Mapping[str, str] = field(default_factory=dict)

    def bundle(self) -> UsableBundle | None:
        if self.enforcement is None:
            return None
        return bundle(
            *self.policies,
            bindings=list(self.bindings),
            enforcement=self.enforcement,
            fallback=self.fallback,
        )


#: The undashed spelling of `AGENT`.
UNDASHED_AGENT = "5c8f1e4200004000800000000000a9e7"


def _raw_ticket(posture_literal: str) -> str:
    """A ticket whose `posture_score` is `posture_literal` as written: `json.dumps`
    would emit `Infinity` for an overflow, which is not JSON."""
    raw = (
        f'{{"agent_id": "{AGENT}", "exp": 4102444800, '
        f'"posture_score": {posture_literal}}}'
    ).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


ENFORCEMENT_CASES = [
    # --- each posture, and no bundle ---
    EnforcementCase(
        "denied",
        (DENIES_EVERYTHING,),
        status=403,
        report=report(),
    ),
    EnforcementCase("denied, observe", (DENIES_EVERYTHING,), enforcement="observe"),
    EnforcementCase("denied, none", (DENIES_EVERYTHING,), enforcement="none"),
    EnforcementCase(
        "allowed",
        (DENIES_EVERYTHING,),
        x_rail=(ticket(posture_score=90),),
    ),
    EnforcementCase("unreadable condition", (policy(BAD_ID, UNREADABLE),), status=503),
    EnforcementCase(
        "unreadable condition, observe",
        (policy(BAD_ID, UNREADABLE),),
        enforcement="observe",
    ),
    EnforcementCase("no bundle", enforcement=None),
    # --- each fallback ---
    # Refused as a policy denial is, so a caller can't map the bindings, and
    # reported naming no policy. Acted on at `enforce` only.
    EnforcementCase(
        "unbound, block", fallback="block", status=403, report=report(policy_id=None)
    ),
    EnforcementCase(
        "unbound, block, with a ticket",
        fallback="block",
        x_rail=(ticket(),),
        status=403,
        report=report(policy_id=None, ticket_state="valid", agent_id=AGENT),
    ),
    EnforcementCase(
        "unbound, block, observe",
        enforcement="observe",
        fallback="block",
        x_rail=(ticket(),),
    ),
    EnforcementCase(
        "unbound, block, none",
        enforcement="none",
        fallback="block",
        x_rail=(ticket(),),
    ),
    EnforcementCase(
        "bound, block",
        (NOTES_ANY_TICKET,),
        (BOUND,),
        fallback="block",
        x_rail=(ticket(),),
    ),
    EnforcementCase("unbound, pass", x_rail=(ticket(),)),
    EnforcementCase(
        "bound to the denying rule",
        (DENIES_EVERYTHING,),
        ({**BOUND, "policy_ids": [DENY_ID]},),
        status=403,
        report=report(key=FULL_KEY),
    ),
    # --- discovery ---
    # A session message is not a call: passed before the bundle is read.
    *[
        EnforcementCase(
            f"discovery {json.loads(body)['method']}", (DENIES_EVERYTHING,), body=body
        )
        for body in DISCOVERY
    ],
    *[
        EnforcementCase(
            f"discovery {json.loads(body)['method']}, block",
            fallback="block",
            body=body,
        )
        for body in DISCOVERY
    ],
    *[
        EnforcementCase(
            f"discovery {json.loads(body)['method']}, no bundle",
            enforcement=None,
            body=body,
        )
        for body in DISCOVERY
    ],
    EnforcementCase(
        "initialize, rule bound to one endpoint",
        (DENIES_ANY_TICKET,),
        ({"endpoint_key": KEY, "mode": "gated", "policy_ids": [DENY_ID]},),
        body=DISCOVERY[0],
        x_rail=(ticket(),),
    ),
    EnforcementCase(
        "call, rule bound to one endpoint",
        (DENIES_ANY_TICKET,),
        ({"endpoint_key": KEY, "mode": "gated", "policy_ids": [DENY_ID]},),
        x_rail=(ticket(),),
        status=403,
        report=report(ticket_state="valid", agent_id=AGENT),
    ),
    # --- keyless and unrecognised keys ---
    # Naming no tool by design leaves the endpoint rules; a `tools/call` with no
    # key faces the whole chain.
    EnforcementCase(
        "keyless",
        (DENIES_EVERYTHING,),
        body=KEYLESS,
        status=403,
        report=report(key=None, resolution="keyless"),
    ),
    EnforcementCase(
        "keyless, block", fallback="block", body=KEYLESS, x_rail=(ticket(),)
    ),
    EnforcementCase(
        "keyless, endpoint rule",
        (DENIES_UNMATCHED_SKILL,),
        body=KEYLESS,
        x_rail=(ticket(),),
    ),
    EnforcementCase(
        "unrecognised, block",
        fallback="block",
        body=call("track_package\n"),
        x_rail=(ticket(),),
        status=403,
        report=report(
            policy_id=None,
            key=None,
            resolution="unrecognised",
            ticket_state="valid",
            agent_id=AGENT,
        ),
    ),
    *[
        EnforcementCase(
            f"unrecognised {name}, endpoint rule",
            (DENIES_UNMATCHED_SKILL,),
            body=body,
            x_rail=(ticket(),),
            status=403,
            report=report(
                policy_id=SKILL_ID,
                key=None,
                resolution="unrecognised",
                ticket_state="valid",
                agent_id=AGENT,
            ),
        )
        for name, body in (
            ("tool name", call("track_package\n")),
            (
                "no tool name",
                json.dumps({"method": "tools/call", "params": {}}).encode(),
            ),
            ("not json", b"not json at all"),
        )
    ],
    # --- repeated headers ---
    # Two tickets are no ticket, and two claims are no claim.
    EnforcementCase(
        "x-rail repeated",
        (DENIES_EVERYTHING,),
        x_rail=(ticket(), ticket(agent_id="5c8f1e42-0000-4000-8000-00000000a9e8")),
        status=403,
        report=report(ticket_state="undecodable"),
    ),
    EnforcementCase(
        "x-rail-status repeated",
        (DENIES_EVERYTHING,),
        x_rail_status=("not-found", "expired"),
        status=403,
        report=report(),
    ),
    # --- too-deep bodies ---
    # Read as unrecognised rather than raising out of `judge`.
    *[
        EnforcementCase(
            f"{depth} deep",
            (DENIES_EVERYTHING,),
            body=deep_call(depth),
            status=403,
            report=report(key=None, resolution="unrecognised"),
        )
        for depth in (MAX_BODY_NESTING_DEPTH + 1, 1000, 10000)
    ],
    *[
        EnforcementCase(
            f"{depth} deep, observe",
            (DENIES_EVERYTHING,),
            enforcement="observe",
            body=deep_call(depth),
        )
        for depth in (MAX_BODY_NESTING_DEPTH + 1, 1000, 10000)
    ],
    # --- the claimed status ---
    EnforcementCase(
        "claimed status",
        (DENIES_EVERYTHING,),
        x_rail_status=("issuer-unreachable",),
        status=403,
        report=report(claimed="issuer-unreachable"),
    ),
    EnforcementCase(
        "claimed status, control characters",
        (DENIES_EVERYTHING,),
        x_rail_status=("not-found\x9b[31mFAKE",),
        status=403,
        report=report(claimed="<unprintable>"),
    ),
    EnforcementCase(
        "claimed status, overlong",
        (DENIES_EVERYTHING,),
        x_rail_status=("n" * 60_000,),
        status=403,
        report=report(claimed="n" * MAX_LOGGED_LENGTH + "…<truncated>"),
    ),
    # --- the claims a report carries ---
    # A claim Rail Center's schema would refuse is dropped, not sent: a 422
    # loses the whole row.
    EnforcementCase(
        "claims of the wrong shape",
        (DENIES_ANY_TICKET,),
        x_rail=(ticket(agent_id="agent-42", posture_score="very-low"),),
        status=403,
        report=report(ticket_state="valid"),
    ),
    *[
        EnforcementCase(
            f"posture_score {claimed}",
            (DENIES_ANY_TICKET,),
            x_rail=(ticket(posture_score=claimed),),
            status=403,
            report=report(ticket_state="valid", agent_id=AGENT),
        )
        for claimed in (True, False)
    ],
    *[
        EnforcementCase(
            f"posture_score {name}",
            (DENIES_ANY_TICKET,),
            x_rail=(_raw_ticket(literal),),
            status=403,
            report=report(ticket_state="valid", agent_id=AGENT),
        )
        for name, literal in (
            ("overflows", "1e400"),
            ("overflows negative", "-1e400"),
            ("long integer", "1" + "0" * 400),
        )
    ],
    *[
        EnforcementCase(
            f"agent_id {name}",
            (DENIES_ANY_TICKET,),
            x_rail=(ticket(agent_id=agent, posture_score=10),),
            status=403,
            report=report(ticket_state="valid", agent_id=agent, posture_score=10),
        )
        for name, agent in (
            ("canonical", AGENT),
            ("uppercase", AGENT.upper()),
            ("undashed", UNDASHED_AGENT),
            ("braced", "{" + AGENT + "}"),
            ("urn", "urn:uuid:" + AGENT),
        )
    ],
    *[
        EnforcementCase(
            f"agent_id {name}",
            (DENIES_ANY_TICKET,),
            x_rail=(ticket(agent_id=agent, posture_score=10),),
            status=403,
            report=report(ticket_state="valid", posture_score=10),
        )
        for name, agent in (
            # Spellings `uuid.UUID` reads and Rail Center refuses.
            ("regrouped", "5c8f1e42000040008000-00000000a9e7"),
            ("leading hyphen", "-" + UNDASHED_AGENT),
            ("hyphen per digit", "-".join(UNDASHED_AGENT)),
            ("braced undashed", "{" + UNDASHED_AGENT + "}"),
            ("urn undashed", "urn:uuid:" + UNDASHED_AGENT),
            # A well-formed spelling followed by anything.
            ("trailing character", AGENT + "X"),
            ("trailing word", AGENT + "-junk"),
            ("trailing space", AGENT + " "),
            ("trailing newline", AGENT + "\n"),
            ("forty hex", UNDASHED_AGENT + "deadbeef"),
            ("urn then brace", "urn:uuid:" + AGENT + "}"),
            ("braced then character", "{" + AGENT + "}x"),
        )
    ],
    # --- the method ---
    EnforcementCase(
        "GET",
        (DENIES_EVERYTHING,),
        method="GET",
        body=b"",
        not_for={"core": "judge is asked about POSTs; each interface passes the rest"},
    ),
]


def enforcement_params(interface: str) -> list:
    """`ENFORCEMENT_CASES` as pytest params for `interface`, ids by row name. A
    row that does not apply is skipped with the table's own reason."""
    return [
        pytest.param(
            case,
            id=case.name,
            marks=(
                [pytest.mark.skip(reason=case.not_for[interface])]
                if interface in case.not_for
                else []
            ),
        )
        for case in ENFORCEMENT_CASES
    ]
