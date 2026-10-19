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
    ticket_fallback: str | None = "pass",
    schema_version: str = "2.0",
):
    """A validated bundle, at `enforce` and both fallbacks `pass` unless asked
    otherwise; `ticket_fallback=None` leaves the field out.

    The fallbacks default to `pass`, unlike Rail Center's `block`: most cases
    call an unbound endpoint, or carry no ticket, and `block` would refuse them
    before the chain.
    """
    return validate_bundle(
        {
            "schema_version": schema_version,
            "content_hash": "v-enforce",
            "policies": list(policies),
            "bindings": bindings or [],
            "enforcement": {"mode": enforcement},
            "binding_fallback": fallback,
            **(
                {"ticket_fallback": ticket_fallback}
                if ticket_fallback is not None
                else {}
            ),
        }
    )


# Denies any request without a usable ticket: the `ticket` source exists only
# for one that decoded and has not expired.
DENIES_EVERYTHING = build_policy(DENY_ID, {"path": "ticket", "op": "not_existing"})

# Denies any valid ticket, whatever its claims, so a malformed claim still
# reaches a report.
DENIES_ANY_TICKET = build_policy(DENY_ID, {"path": "ticket", "op": "existing"})

# Holds for a call this gateway composed no key for, keyless or unrecognised.
DENIES_NO_KEY = build_policy(
    SKILL_ID, {"path": "request.endpoint_key", "op": "not_existing"}
)

# Admits only `acme`: one rule refuses a different value, one refuses none.
ALLOWS_TENANT = (
    build_policy(
        DENY_ID, {"path": "request.headers.x-tenant", "op": "ne", "value": "acme"}
    ),
    build_policy(
        SKILL_ID,
        {"path": "request.headers.x-tenant", "op": "not_existing"},
        priority=2,
    ),
)

# Keyed on a request header.
DENIES_TENANT = build_policy(
    DENY_ID, {"path": "request.headers.x-tenant", "op": "eq", "value": "acme"}
)

# Outside the grammar, so the bundle can't be applied.
UNREADABLE = {"path": "invented_field", "op": "eq", "value": 1}

# Alerts on any ticket and never denies, so a binding can name a policy.
NOTES_ANY_TICKET = build_policy(
    SKILL_ID, {"path": "ticket", "op": "existing"}, action="alert"
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
    """An `x-rail` header carrying `claims`, unpadded as the mint emits it.
    `score` is `posture.overall.score`."""
    claims.setdefault("agent_id", AGENT)
    claims.setdefault("exp", 4102444800)  # 2100-01-01, comfortably unexpired
    if "score" in claims:
        claims["posture"] = {"overall": {"score": claims.pop("score")}}
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
    fallback: str | None = None,
    **claims: Any,
) -> dict[str, Any]:
    """A denial report as Rail Center receives it, less `denied_at`."""
    metadata = {"endpoint_resolution": resolution, "x-rail-status": ticket_state}
    if claimed is not None:
        metadata["claimed-x-rail-status"] = claimed
    if fallback is not None:
        metadata["fallback"] = fallback
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
    # Any other request headers, as `(name, value)` pairs.
    headers: tuple[tuple[str, str], ...] = ()
    ticket_fallback: str | None = "pass"
    schema_version: str = "2.0"
    # The refusal's status; None where the call is forwarded.
    status: int | None = None
    # The denial report less `denied_at`; None where none is sent.
    report: Mapping[str, Any] | None = None
    # Parts of one line the row must log; empty where no line is asserted.
    # Where a row's whole effect is a warning, the warning is the row.
    logged: tuple[str, ...] = ()
    not_for: Mapping[str, str] = field(default_factory=dict)

    def get_bundle(self) -> UsableBundle | None:
        if self.enforcement is None:
            return None
        return build_bundle(
            *self.policies,
            bindings=list(self.bindings),
            enforcement=self.enforcement,
            fallback=self.fallback,
            ticket_fallback=self.ticket_fallback,
            schema_version=self.schema_version,
        )


# A stored ticket's `id`.
TICKET = "5c8f1e42-0000-4000-8000-00000000c001"

# The undashed spelling of `TICKET`.
UNDASHED_TICKET = TICKET.replace("-", "")


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
        x_rail=(encode_ticket(score=90),),
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
        report=build_report(policy_id=None, fallback="binding"),
    ),
    EnforcementCase(
        "unbound, block, with a ticket",
        fallback="block",
        x_rail=(encode_ticket(),),
        status=403,
        report=build_report(policy_id=None, ticket_state="valid", fallback="binding"),
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
        report=build_report(ticket_state="valid"),
    ),
    # --- keyless and unrecognised keys ---
    # Both face the whole chain; only the binding fallback tells them apart.
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
    # No rule is dropped for a keyless message: one on the key reads it absent.
    EnforcementCase(
        "keyless, endpoint rule",
        (DENIES_NO_KEY,),
        body=KEYLESS,
        x_rail=(encode_ticket(),),
        status=403,
        report=build_report(
            policy_id=SKILL_ID, key=None, resolution="keyless", ticket_state="valid"
        ),
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
            fallback="binding",
        ),
    ),
    *[
        EnforcementCase(
            f"unrecognised {name}, endpoint rule",
            (DENIES_NO_KEY,),
            body=body,
            x_rail=(encode_ticket(),),
            status=403,
            report=build_report(
                policy_id=SKILL_ID,
                key=None,
                resolution="unrecognised",
                ticket_state="valid",
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
    # Only the ticket's `id`, and only in a spelling Rail Center reads: a 422
    # loses the whole report. Nothing else the ticket says is reported.
    EnforcementCase(
        "claims are not reported",
        (DENIES_ANY_TICKET,),
        x_rail=(encode_ticket(id=TICKET, score=72.5),),
        status=403,
        report=build_report(ticket_state="valid", ticket_id=TICKET),
    ),
    *[
        EnforcementCase(
            f"ticket id {name}",
            (DENIES_ANY_TICKET,),
            x_rail=(encode_ticket(id=ticket_id),),
            status=403,
            report=build_report(ticket_state="valid", **reported),
        )
        for name, ticket_id, reported in (
            ("canonical", TICKET, {"ticket_id": TICKET}),
            ("uppercase", TICKET.upper(), {"ticket_id": TICKET.upper()}),
            ("undashed", UNDASHED_TICKET, {"ticket_id": UNDASHED_TICKET}),
            ("braced", "{" + TICKET + "}", {"ticket_id": "{" + TICKET + "}"}),
            ("urn", "urn:uuid:" + TICKET, {"ticket_id": "urn:uuid:" + TICKET}),
            # Spellings `uuid.UUID` reads and Rail Center refuses.
            ("regrouped", "5c8f1e42000040008000-0000000000c001", {}),
            ("leading hyphen", "-" + UNDASHED_TICKET, {}),
            ("hyphen per digit", "-".join(UNDASHED_TICKET), {}),
            ("braced undashed", "{" + UNDASHED_TICKET + "}", {}),
            ("urn undashed", "urn:uuid:" + UNDASHED_TICKET, {}),
            # A well-formed spelling followed by anything.
            ("trailing character", TICKET + "X", {}),
            ("trailing newline", TICKET + "\n", {}),
            ("forty hex", UNDASHED_TICKET + "deadbeef", {}),
            ("not a uuid", "ticket-7", {}),
            ("a number", 7, {}),
        )
    ],
    # --- the ticket fallback ---
    # No usable ticket is the bundle's to decide, before the binding fallback
    # and the chain, and acted on at `enforce` only.
    *[
        EnforcementCase(
            f"no usable ticket, block ({state})",
            ticket_fallback="block",
            x_rail=x_rail,
            status=403,
            report=build_report(policy_id=None, ticket_state=state, fallback="ticket"),
        )
        for state, x_rail in (
            ("absent", ()),
            ("undecodable", ("!!!",)),
            ("malformed", (encode_ticket(exp="soon"),)),
            ("expired", (encode_ticket(exp=1),)),
        )
    ],
    EnforcementCase(
        "no usable ticket, block, a valid ticket is judged",
        ticket_fallback="block",
        x_rail=(encode_ticket(),),
    ),
    EnforcementCase(
        "no usable ticket, the fallback is block when the bundle names none",
        ticket_fallback=None,
        status=403,
        report=build_report(policy_id=None, fallback="ticket"),
    ),
    # At `observe` the warning is the whole of what `block` does: the preview
    # an operator reads before moving to `enforce`.
    EnforcementCase(
        "no usable ticket, block, observe",
        ticket_fallback="block",
        enforcement="observe",
        logged=(
            "would deny ",
            "(ticket absent, ticket_fallback=block) — this mode enforces nothing",
        ),
    ),
    EnforcementCase(
        "no usable ticket, block, none", ticket_fallback="block", enforcement="none"
    ),
    EnforcementCase(
        "no usable ticket, pass, walks the chain",
        (DENIES_EVERYTHING,),
        status=403,
        report=build_report(),
    ),
    EnforcementCase(
        "no usable ticket, before the binding fallback",
        ticket_fallback="block",
        fallback="block",
        status=403,
        report=build_report(policy_id=None, fallback="ticket"),
    ),
    # --- a 1.x bundle ---
    # Read in the `{field, operator}` grammar, and with no `ticket_fallback` the
    # chain's own rule decides a missing ticket and is named in the report.
    EnforcementCase(
        "v1, no ticket, the chain's rule decides",
        (build_policy(DENY_ID, {"field": "x_rail_header", "operator": "missing"}),),
        ticket_fallback=None,
        schema_version="1.0",
        status=403,
        report=build_report(),
    ),
    EnforcementCase(
        "v1, a flat claim",
        (
            build_policy(
                DENY_ID, {"field": "posture_score", "operator": "lt", "value": 40}
            ),
        ),
        ticket_fallback=None,
        schema_version="1.0",
        x_rail=(encode_ticket(posture_score=10, id=TICKET),),
        status=403,
        report=build_report(ticket_state="valid", ticket_id=TICKET),
    ),
    EnforcementCase(
        "v1, a v2 condition is uninterpretable",
        (build_policy(DENY_ID, {"path": "ticket", "op": "existing"}),),
        ticket_fallback=None,
        schema_version="1.0",
        x_rail=(encode_ticket(),),
        status=503,
    ),
    EnforcementCase(
        "v2, a v1 condition is uninterpretable",
        (build_policy(DENY_ID, {"field": "agent_id", "operator": "present"}),),
        x_rail=(encode_ticket(),),
        status=503,
    ),
    # --- request headers ---
    EnforcementCase(
        "header rule",
        (DENIES_TENANT,),
        x_rail=(encode_ticket(),),
        headers=(("X-Tenant", "acme"),),
        status=403,
        report=build_report(ticket_state="valid"),
    ),
    EnforcementCase(
        "header rule, another value",
        (DENIES_TENANT,),
        x_rail=(encode_ticket(),),
        headers=(("x-tenant", "other"),),
    ),
    EnforcementCase(
        "header rule, no header",
        (DENIES_TENANT,),
        x_rail=(encode_ticket(),),
    ),
    # Every value of a repeated header reaches the rule, as a list, and `eq`
    # holds on it only because every value equals.
    EnforcementCase(
        "header rule, repeated",
        (DENIES_TENANT,),
        x_rail=(encode_ticket(),),
        headers=(("X-Tenant", "acme"), ("x-tenant", "acme")),
        status=403,
        report=build_report(ticket_state="valid"),
    ),
    # The allowlist a policy writes for a header: block on `ne`, block on
    # `not_existing`. A foreign value repeated, beside the allowed one, or on
    # one comma-separated line is refused on every host alike.
    *[
        EnforcementCase(
            f"header allowlist, {name}",
            ALLOWS_TENANT,
            x_rail=(encode_ticket(),),
            headers=headers,
            **(
                {
                    "status": 403,
                    "report": build_report(policy_id=by, ticket_state="valid"),
                }
                if by
                else {}
            ),
        )
        for name, headers, by in (
            ("the allowed value", (("x-tenant", "acme"),), None),
            ("the allowed value repeated", (("x-tenant", "acme"),) * 2, None),
            ("a foreign value", (("x-tenant", "evil"),), DENY_ID),
            ("no header", (), SKILL_ID),
            ("a foreign value repeated", (("x-tenant", "evil"),) * 2, DENY_ID),
            (
                "a foreign value on a second line",
                (("x-tenant", "acme"), ("x-tenant", "evil")),
                DENY_ID,
            ),
            ("a foreign value after a comma", (("x-tenant", "acme, evil"),), DENY_ID),
        )
    ],
    # A wildcard denylist is one rule: `matches` holds when any value does.
    *[
        EnforcementCase(
            f"header denylist, {name}",
            (
                build_policy(
                    DENY_ID,
                    {
                        "path": "request.headers.user-agent",
                        "op": "matches",
                        "value": "*sqlmap*",
                    },
                ),
            ),
            x_rail=(encode_ticket(),),
            headers=(("User-Agent", value),),
            **(
                {"status": 403, "report": build_report(ticket_state="valid")}
                if refused
                else {}
            ),
        )
        for name, value, refused in (
            ("a listed tool", "sqlmap/1.7", True),
            ("a listed tool beside another value", "sqlmap/1.7, x", True),
            ("a browser", "Mozilla/5.0 (KHTML, like Gecko) Chrome/129.0", False),
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
