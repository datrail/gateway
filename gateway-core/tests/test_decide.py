"""The one walk rule that is this gateway's own rather than the contract's.

Everything else about the walk is pinned by `tests/vectors/v1/decide.json`
and `v2/decide.json`. This rule cannot be: every vector is handed an endpoint key, so no vector can express
what happens when there is no key at all.

MCP is why there is such a case. A call's identity lives in the message rather
than the URL, and only `tools/call` names a tool — `resources/read` and
`prompts/get` name none, and a `tools/call` whose tool name is unusable
resolves to no key either. (`initialize`, `tools/list` and the other session
messages never reach this walk: `src/gateway/core/endpoint.py` resolves them to
`discovery` and the enforcement layer forwards them.) The rule the rest land on:
**no key is not a pass.** In a `2.x` bundle the whole chain judges a keyless
message, and a rule on `request.endpoint_key` reads the key as absent. In a
`1.x` bundle the endpoint-derived fields leave a keyless chain, and stay in an
unrecognised call's.
"""

import base64
import json
from typing import Any

import pytest

from gateway.core.bundle.conditions import ConditionInput
from gateway.core.bundle.decide import chain_for, decide
from gateway.core.bundle.validate import validate_bundle
from gateway.core.ticket import parse_rail_header

NOW = 1700000000
KEY = "delivery.track_package"
LOW_SCORE = "5c8f1e42-0000-4000-8000-0000000000d1"
BY_KEY = "5c8f1e42-0000-4000-8000-0000000000a1"


def rule(pid: str, condition: dict[str, Any], priority: int = 1) -> dict[str, Any]:
    return {
        "id": pid,
        "name": f"policy {pid[-2:]}",
        "priority": priority,
        "condition": condition,
        "action": "block",
        "enabled": True,
    }


def bundle(*policies: dict[str, Any], bindings: list[dict[str, Any]] | None = None):
    return validate_bundle(
        {
            "schema_version": "2.0",
            "content_hash": "v-keyless",
            "policies": list(policies)
            or [
                rule(
                    LOW_SCORE,
                    {"path": "ticket.posture.overall.score", "op": "lt", "value": 40},
                ),
                rule(
                    BY_KEY,
                    {
                        "path": "request.endpoint_key",
                        "op": "matches",
                        "value": "delivery.*",
                    },
                    priority=2,
                ),
            ],
            "bindings": bindings or [],
        }
    )


def ticket(**claims: Any) -> str:
    """An `x-rail` header carrying `claims`, unpadded as the mint emits it.
    `score` is `posture.overall.score`."""
    claims.setdefault("exp", 4102444800)  # 2100-01-01
    if "score" in claims:
        claims["posture"] = {"overall": {"score": claims.pop("score")}}
    raw = json.dumps(claims).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def request(endpoint_key: str | None, header: str | None = None) -> ConditionInput:
    return ConditionInput(
        ticket=parse_rail_header(header, NOW), endpoint_key=endpoint_key
    )


def test_a_call_naming_no_endpoint_faces_the_whole_chain():
    """No binding narrows a keyless message — there is no key to look one up
    with — and no rule leaves the chain for it either. Returning an empty chain
    instead would allow every keyless message, `resources/read` with no ticket
    at all."""
    assert len(chain_for(bundle(), None)) == 2
    assert len(chain_for(bundle(), KEY)) == 2


def test_a_keyless_call_is_denied_by_a_rule_about_the_ticket():
    verdict = decide(bundle(), request(None, ticket(score=10)))

    assert verdict.allowed is False
    assert verdict.denied_by is not None
    assert verdict.denied_by.id == LOW_SCORE


def test_a_keyless_call_is_not_narrowed_by_another_endpoints_binding():
    """A binding is looked up by key. With no key there is nothing to look up,
    and a reader that fell back to *some* endpoint's narrowing would judge the
    message by whichever rules happened to be bound elsewhere."""
    narrowed = bundle(
        bindings=[{"endpoint_key": KEY, "mode": "gated", "policy_ids": [BY_KEY]}]
    )

    assert len(chain_for(narrowed, None)) == 2
    assert len(chain_for(narrowed, KEY)) == 1


@pytest.mark.parametrize(
    ("op", "operand"),
    [
        ("eq", KEY),
        ("ne", "delivery.other"),
        ("in", [KEY]),
        ("matches", "delivery.*"),
        ("existing", None),
    ],
)
def test_a_comparison_on_the_key_does_not_fire_without_one(op, operand):
    """Every operator but `not_existing` declines against an absence, so a rule
    written for an endpoint does not deny a message that names none."""
    condition = {"path": "request.endpoint_key", "op": op}
    if operand is not None:
        condition["value"] = operand
    verdict = decide(bundle(rule(BY_KEY, condition)), request(None, ticket()))
    assert verdict.allowed is True


def test_not_existing_on_the_key_fires_without_one():
    """The one operator that asks about the absence answers it: a rule meaning
    "deny anything that named no tool" is written, and does what it says."""
    held = bundle(rule(BY_KEY, {"path": "request.endpoint_key", "op": "not_existing"}))

    assert decide(held, request(None, ticket())).allowed is False
    assert decide(held, request(KEY, ticket())).allowed is True


def test_a_v1_chain_drops_its_endpoint_rules_for_a_keyless_message_only():
    """`skill_match missing` holds against an absent key, so in the `1.x`
    grammar it leaves the chain of a message that names no tool by design —
    and stays in that of a `tools/call` this gateway declined to key, which
    did name one."""
    held = validate_bundle(
        {
            "schema_version": "1.0",
            "content_hash": "v-keyless-v1",
            "policies": [rule(BY_KEY, {"field": "skill_match", "operator": "missing"})],
            "bindings": [],
        }
    )

    assert chain_for(held, None) == ()
    assert decide(held, request(None, ticket())).allowed is True
    assert decide(held, request(None, ticket()), keyless=False).allowed is False
