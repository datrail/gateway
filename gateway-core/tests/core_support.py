"""Helpers for the gateway-core suite and the members built on it, including
the enforcement contract table every interface runs."""

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

# The `agent_id` every ticket here carries unless a case says otherwise.
AGENT = "5c8f1e42-0000-4000-8000-00000000a9e7"


def build_policy(
    pid: str, condition: dict[str, Any], *, priority: int = 1, action="block"
):
    return {
        "id": pid,
        "name": f"policy {pid[-2:]}",
        "priority": priority,
        "condition": condition,
        "action": action,
        "enabled": True,
    }


def build_bundle(
    *policies: dict[str, Any],
    bindings: list[dict[str, Any]] | None = None,
    enforcement: str = "enforce",
    fallback: str = "pass",
):
    """A validated bundle, at `enforce` and fallback `pass` unless asked otherwise.

    The fallback defaults to `pass`, unlike Rail Center's `block`: most cases
    call an unbound endpoint, and `block` would refuse them before the chain.
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


# The seeded "deny unknown agents": denies any request without a usable ticket.
DENIES_EVERYTHING = build_policy(
    DENY_ID, {"field": "x_rail_header", "operator": "missing"}
)

# Denies any valid ticket, whatever its claims, so a malformed claim still
# reaches a report.
DENIES_ANY_TICKET = build_policy(DENY_ID, {"field": "agent_id", "operator": "present"})

# Keyed on the endpoint: dropped for a keyless message, kept for an
# unrecognised call.
DENIES_UNMATCHED_SKILL = build_policy(
    SKILL_ID, {"field": "skill_match", "operator": "missing"}
)

# Outside the grammar, so the bundle can't be applied.
UNREADABLE = {"field": "invented_field", "operator": "eq", "value": 1}

# Alerts on any ticket and never denies, so a binding can name a policy.
NOTES_ANY_TICKET = build_policy(
    SKILL_ID, {"field": "agent_id", "operator": "present"}, action="alert"
)

# The full key, slug included, as Rail Center publishes it: the gateway strips
# the slug before matching.
FULL_KEY = f"{SLUG}#{KEY}"
BOUND = {"endpoint_key": FULL_KEY, "mode": "gated", "policy_ids": [SKILL_ID]}


class Holder:
    """A bundle holder that holds what the test says: `judge` only calls
    `current()`."""

    def __init__(self, held=None):
        self.held = held

    def current(self):
        return self.held


def encode_ticket(**claims: Any) -> str:
    """An `x-rail` header carrying `claims`, unpadded as the mint emits it."""
    claims.setdefault("agent_id", AGENT)
    claims.setdefault("exp", 4102444800)  # 2100-01-01, comfortably unexpired
    raw = json.dumps(claims).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def build_call(tool: str = "track_package") -> bytes:
    return json.dumps({"method": "tools/call", "params": {"name": tool}}).encode()


KEYLESS = json.dumps({"method": "resources/read"}).encode()
DISCOVERY = tuple(
    json.dumps({"method": m}).encode()
    for m in ("initialize", "notifications/initialized", "tools/list")
)


def build_deep_call(depth: int) -> bytes:
    """A `tools/call` nesting `depth` levels."""
    inner = "[" * (depth - 3) + "]" * (depth - 3)
    return (
        '{"method": "tools/call", "params": {"name": "track_package", '
        f'"arguments": {{"q": {inner}}}}}}}'
    ).encode()


# The refusal bodies, as literals: they are the wire format.
REASONS = {403: "denied by policy", 503: "policy ruleset cannot be applied"}


def build_report(
    *,
    policy_id: str | None = DENY_ID,
    key: str | None = KEY,
    resolution: str = "resolved",
    ticket_state: str = "absent",
    claimed: str | None = None,
    **claims: Any,
) -> dict[str, Any]:
    """A denial report as Rail Center receives it, less `denied_at`."""
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
    """One row of the contract: a held bundle, one request, and what the caller
    and Rail Center get. Standalone's behaviour is the definition; `not_for`
    names the interfaces a row is skipped for, and why."""

    name: str
    policies: tuple[dict[str, Any], ...] = ()
    bindings: tuple[dict[str, Any], ...] = ()
    # The bundle's posture; None where no bundle is held.
    enforcement: str | None = "enforce"
    fallback: str = "pass"
    method: str = "POST"
    path: str = "/mcp"
    body: bytes = build_call()
    x_rail: tuple[str, ...] = ()
    x_rail_status: tuple[str, ...] = ()
    # The refusal's status; None where the call is forwarded.
    status: int | None = None
    # The denial report less `denied_at`; None where none is sent.
    report: Mapping[str, Any] | None = None
    not_for: Mapping[str, str] = field(default_factory=dict)

    def get_bundle(self) -> UsableBundle | None:
        if self.enforcement is None:
            return None
        return build_bundle(
            *self.policies,
            bindings=list(self.bindings),
            enforcement=self.enforcement,
            fallback=self.fallback,
        )


# The undashed spelling of `AGENT`.
UNDASHED_AGENT = "5c8f1e4200004000800000000000a9e7"


def _encode_raw_ticket(posture_literal: str) -> str:
    """A ticket with `posture_literal` as written: `json.dumps` turns an
    overflow into `Infinity`, which isn't JSON."""
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
        report=build_report(),
    ),
    EnforcementCase("denied, observe", (DENIES_EVERYTHING,), enforcement="observe"),
    EnforcementCase("denied, none", (DENIES_EVERYTHING,), enforcement="none"),
    EnforcementCase(
        "allowed",
        (DENIES_EVERYTHING,),
        x_rail=(encode_ticket(posture_score=90),),
    ),
    EnforcementCase(
        "unreadable condition", (build_policy(BAD_ID, UNREADABLE),), status=503
    ),
    EnforcementCase(
        "unreadable condition, observe",
        (build_policy(BAD_ID, UNREADABLE),),
        enforcement="observe",
    ),
    EnforcementCase("no bundle", enforcement=None),
    # --- each fallback ---
    # Refused like a policy denial, reported with no policy, at `enforce` only.
    EnforcementCase(
        "unbound, block",
        fallback="block",
        status=403,
        report=build_report(policy_id=None),
    ),
    EnforcementCase(
        "unbound, block, with a ticket",
        fallback="block",
        x_rail=(encode_ticket(),),
        status=403,
        report=build_report(policy_id=None, ticket_state="valid", agent_id=AGENT),
    ),
    EnforcementCase(
        "unbound, block, observe",
        enforcement="observe",
        fallback="block",
        x_rail=(encode_ticket(),),
    ),
    EnforcementCase(
        "unbound, block, none",
        enforcement="none",
        fallback="block",
        x_rail=(encode_ticket(),),
    ),
    EnforcementCase(
        "bound, block",
        (NOTES_ANY_TICKET,),
        (BOUND,),
        fallback="block",
        x_rail=(encode_ticket(),),
    ),
    EnforcementCase("unbound, pass", x_rail=(encode_ticket(),)),
    EnforcementCase(
        "bound to the denying rule",
        (DENIES_EVERYTHING,),
        ({**BOUND, "policy_ids": [DENY_ID]},),
        status=403,
        report=build_report(key=FULL_KEY),
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
        x_rail=(encode_ticket(),),
    ),
    EnforcementCase(
        "call, rule bound to one endpoint",
        (DENIES_ANY_TICKET,),
        ({"endpoint_key": KEY, "mode": "gated", "policy_ids": [DENY_ID]},),
        x_rail=(encode_ticket(),),
        status=403,
        report=build_report(ticket_state="valid", agent_id=AGENT),
    ),
    # --- keyless and unrecognised keys ---
    # Keyless skips the endpoint rules; an unrecognised call faces the whole chain.
    EnforcementCase(
        "keyless",
        (DENIES_EVERYTHING,),
        body=KEYLESS,
        status=403,
        report=build_report(key=None, resolution="keyless"),
    ),
    EnforcementCase(
        "keyless, block", fallback="block", body=KEYLESS, x_rail=(encode_ticket(),)
    ),
    EnforcementCase(
        "keyless, endpoint rule",
        (DENIES_UNMATCHED_SKILL,),
        body=KEYLESS,
        x_rail=(encode_ticket(),),
    ),
    EnforcementCase(
        "unrecognised, block",
        fallback="block",
        body=build_call("track_package\n"),
        x_rail=(encode_ticket(),),
        status=403,
        report=build_report(
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
            x_rail=(encode_ticket(),),
            status=403,
            report=build_report(
                policy_id=SKILL_ID,
                key=None,
                resolution="unrecognised",
                ticket_state="valid",
                agent_id=AGENT,
            ),
        )
        for name, body in (
            ("tool name", build_call("track_package\n")),
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
        x_rail=(
            encode_ticket(),
            encode_ticket(agent_id="5c8f1e42-0000-4000-8000-00000000a9e8"),
        ),
        status=403,
        report=build_report(ticket_state="undecodable"),
    ),
    EnforcementCase(
        "x-rail-status repeated",
        (DENIES_EVERYTHING,),
        x_rail_status=("not-found", "expired"),
        status=403,
        report=build_report(),
    ),
    # --- too-deep bodies ---
    # Read as unrecognised rather than raising out of `judge`.
    *[
        EnforcementCase(
            f"{depth} deep",
            (DENIES_EVERYTHING,),
            body=build_deep_call(depth),
            status=403,
            report=build_report(key=None, resolution="unrecognised"),
        )
        for depth in (MAX_BODY_NESTING_DEPTH + 1, 1000, 10000)
    ],
    *[
        EnforcementCase(
            f"{depth} deep, observe",
            (DENIES_EVERYTHING,),
            enforcement="observe",
            body=build_deep_call(depth),
        )
        for depth in (MAX_BODY_NESTING_DEPTH + 1, 1000, 10000)
    ],
    # --- the claimed status ---
    EnforcementCase(
        "claimed status",
        (DENIES_EVERYTHING,),
        x_rail_status=("issuer-unreachable",),
        status=403,
        report=build_report(claimed="issuer-unreachable"),
    ),
    EnforcementCase(
        "claimed status, control characters",
        (DENIES_EVERYTHING,),
        x_rail_status=("not-found\x9b[31mFAKE",),
        status=403,
        report=build_report(claimed="<unprintable>"),
    ),
    EnforcementCase(
        "claimed status, overlong",
        (DENIES_EVERYTHING,),
        x_rail_status=("n" * 60_000,),
        status=403,
        report=build_report(claimed="n" * MAX_LOGGED_LENGTH + "…<truncated>"),
    ),
    # --- the claims a report carries ---
    # A claim Rail Center would refuse is dropped: a 422 loses the whole report.
    EnforcementCase(
        "claims of the wrong shape",
        (DENIES_ANY_TICKET,),
        x_rail=(encode_ticket(agent_id="agent-42", posture_score="very-low"),),
        status=403,
        report=build_report(ticket_state="valid"),
    ),
    *[
        EnforcementCase(
            f"posture_score {claimed}",
            (DENIES_ANY_TICKET,),
            x_rail=(encode_ticket(posture_score=claimed),),
            status=403,
            report=build_report(ticket_state="valid", agent_id=AGENT),
        )
        for claimed in (True, False)
    ],
    *[
        EnforcementCase(
            f"posture_score {name}",
            (DENIES_ANY_TICKET,),
            x_rail=(_encode_raw_ticket(literal),),
            status=403,
            report=build_report(ticket_state="valid", agent_id=AGENT),
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
            x_rail=(encode_ticket(agent_id=agent, posture_score=10),),
            status=403,
            report=build_report(ticket_state="valid", agent_id=agent, posture_score=10),
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
            x_rail=(encode_ticket(agent_id=agent, posture_score=10),),
            status=403,
            report=build_report(ticket_state="valid", posture_score=10),
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


def get_enforcement_params(interface: str) -> list:
    """`ENFORCEMENT_CASES` as pytest params for `interface`, skipping the rows
    `not_for` it."""
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
