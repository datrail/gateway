"""The one walk rule that is this gateway's own rather than the contract's.

Everything else about the walk is pinned by `tests/vectors/decide.json`, which
is transcribed from rail-center's `docs/policy-evaluation-contract.md`. This
rule cannot be: the contract's `decide` is always handed an endpoint key, and
`endpoint_key` is modelled there as an argument rather than a claim that may be
absent. So no vector can express what happens when there is no key at all.

MCP is why there is such a case. A call's identity lives in the message rather
than the URL, and only `tools/call` names a tool — `initialize`,
`notifications/initialized` and `tools/list` name none, and a `tools/call`
whose tool name is unusable resolves to no key either. `gateway/endpoint.py`
states the rule those land on: **no key is not a pass.** Both keyless outcomes
are judged by the entire chain, because admitting what could not be identified
would let an unidentified caller enumerate the tool surface with `tools/list`.

What is deliberately *not* pinned here is what a `skill_match` rule should mean
for a message naming no tool. A rule keyed on the endpoint declines to hold
against an absence, which is settled; whether a rule about the skill covering
an endpoint should fire on a message that names none is not, and it cannot be
settled in one implementation — the contract has no position on it, and the two
sides have to agree or they disagree exactly where it matters.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from gateway.bundle.conditions import ConditionInput
from gateway.bundle.decide import chain_for, decide
from gateway.bundle.validate import validate_bundle
from gateway.ticket import parse_rail_header

NOW = 1700000000
KEY = "delivery.track_package"
LOW_SCORE = "5c8f1e42-0000-4000-8000-0000000000d1"
BY_KEY = "5c8f1e42-0000-4000-8000-0000000000a1"


def bundle(bindings: list[dict[str, Any]] | None = None):
    return validate_bundle(
        {
            "version": "v-keyless",
            "policies": [
                {
                    "id": LOW_SCORE,
                    "name": "deny a low-scoring agent",
                    "priority": 1,
                    "condition": {
                        "field": "posture_score",
                        "operator": "lt",
                        "value": 40,
                    },
                    "action": "block",
                    "enabled": True,
                },
                {
                    "id": BY_KEY,
                    "name": "deny this data source",
                    "priority": 2,
                    "condition": {
                        "field": "endpoint_key",
                        "operator": "matches",
                        "value": "delivery.*",
                    },
                    "action": "block",
                    "enabled": True,
                },
            ],
            "bindings": bindings or [],
            "rejected": [],
        }
    )


def ticket(**claims: Any) -> str:
    """An `x-rail` header carrying `claims`, unpadded as the mint emits it."""
    claims.setdefault("agent_id", "agent-1")
    claims.setdefault("exp", 4102444800)  # 2100-01-01
    raw = json.dumps(claims).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def request(endpoint_key: str | None, header: str | None = None) -> ConditionInput:
    return ConditionInput(
        ticket=parse_rail_header(header, NOW), endpoint_key=endpoint_key
    )


def test_a_call_naming_no_endpoint_keeps_every_rule_that_can_ask_about_it():
    """No binding narrows a keyless message — there is no key to look one up
    with — and only the rules *about the endpoint* leave the chain.

    Returning an empty chain instead would allow every message that is not a
    `tools/call`: the handshake, and the `tools/list` an unidentified caller
    would enumerate the tool surface with. Returning the whole chain would deny
    the handshake for a conforming agent. This is the line between the two, and
    both failures are one edit away in opposite directions."""
    assert [p.id for p in chain_for(bundle(), None)] == [LOW_SCORE]
    assert len(chain_for(bundle(), KEY)) == 2


def test_a_keyless_call_is_denied_by_a_rule_about_the_ticket():
    """Every rule that can meaningfully ask about a keyless message still does.

    This is the half that must survive the narrowing: `deny unknown agents`
    keys on the ticket, so a caller with no ticket is stopped at `initialize`
    rather than let through to enumerate the tool surface."""
    verdict = decide(bundle(), request(None, ticket(posture_score=10)))

    assert verdict.allowed is False
    assert verdict.denied_by is not None
    assert verdict.denied_by.id == LOW_SCORE


def test_a_keyless_call_is_not_narrowed_by_another_endpoints_binding():
    """A binding is looked up by key. With no key there is nothing to look up,
    and a reader that fell back to *some* endpoint's narrowing would judge the
    handshake by whichever rules happened to be bound elsewhere.

    What is dropped from a keyless chain is dropped for being *about the
    endpoint*, never for being bound to one — so the ticket rule survives here
    and the `endpoint_key` rule does not, whatever the bindings say.
    """
    narrowed = bundle([{"endpoint_key": KEY, "mode": "gated", "policy_ids": [BY_KEY]}])

    assert [p.id for p in chain_for(narrowed, None)] == [LOW_SCORE]
    assert len(chain_for(narrowed, KEY)) == 1


def test_an_endpoint_rule_is_dropped_from_a_keyless_chain():
    """A rule about the endpoint asks a question with no subject when no
    endpoint was named, so it leaves the chain rather than resolving to absent.

    Absent is the answer that makes `skill_match missing` *hold*, which is why
    letting these resolve rather than dropping them denied every handshake for
    an agent whose declared skills were exactly right."""
    only_by_key = validate_bundle(
        {
            "version": "v-keyless",
            "policies": [
                {
                    "id": BY_KEY,
                    "name": "deny this data source",
                    "priority": 2,
                    "condition": {
                        "field": "endpoint_key",
                        "operator": "matches",
                        "value": "delivery.*",
                    },
                    "action": "block",
                    "enabled": True,
                }
            ],
            "bindings": [],
            "rejected": [],
        }
    )

    assert chain_for(only_by_key, None) == ()
    assert len(chain_for(only_by_key, KEY)) == 1
    verdict = decide(only_by_key, request(None, ticket(posture_score=10)))
    assert verdict.allowed is True


def test_every_operator_endpoint_key_admits_declines_against_an_absence():
    """All four of them, since it is the whole basis of the rule above.

    The field admits `eq`, `ne`, `in` and `matches` and admits neither `missing`
    nor `present` — so there is no operator through which a rule about an
    endpoint can fire on a request naming none, and a keyless call being judged
    by the whole chain is not a keyless call being denied by every rule in it.
    """
    for operator, operand in [
        ("eq", KEY),
        ("ne", "delivery.other"),
        ("in", [KEY]),
        ("matches", "delivery.*"),
    ]:
        rule = validate_bundle(
            {
                "version": "v-keyless",
                "policies": [
                    {
                        "id": BY_KEY,
                        "name": f"deny by {operator}",
                        "priority": 1,
                        "condition": {
                            "field": "endpoint_key",
                            "operator": operator,
                            "value": operand,
                        },
                        "action": "block",
                        "enabled": True,
                    }
                ],
                "bindings": [],
                "rejected": [],
            }
        )
        verdict = decide(rule, request(None, ticket(posture_score=10)))
        assert verdict.allowed is True, operator
