"""The published schemas are checked, not merely shipped.

`schemas/` is a contract other people build against, and a schema with a typo
in it is worse than no schema: it validates the wrong thing quietly, and every
consumer inherits the mistake. Three properties are worth holding, and all
three are cheap.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

SCHEMAS = Path(__file__).parent.parent / "schemas"
VECTORS = Path(__file__).parent / "vectors"

NAMES = ["x-rail-ticket.schema.json", "policy-bundle.schema.json"]


def _schema(name: str) -> dict[str, Any]:
    return json.loads((SCHEMAS / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", NAMES)
def test_the_schema_is_valid_json_schema(name: str) -> None:
    """It says draft 2020-12, so it has to be one."""
    Draft202012Validator.check_schema(_schema(name))


@pytest.mark.parametrize("name", NAMES)
def test_the_schema_satisfies_its_own_examples(name: str) -> None:
    """An example that its schema rejects is the commonest way this goes wrong.

    The example is what a reader copies, so the two disagreeing means everyone
    who follows the file is wrong in the same way.
    """
    schema = _schema(name)
    validator = Draft202012Validator(schema)
    assert schema["examples"], name
    for example in schema["examples"]:
        validator.validate(example)


def test_the_bundle_schema_accepts_what_rail_center_emits() -> None:
    """The contract's worked example, which is what the control plane produces.

    Deliberately not "every usable vector": the validator accepts more than the
    schema describes, because the schema says what Rail Center emits while the
    validator has to read what anyone sends. A policy named `42`, or one
    `enabled` with an empty list, is a bundle no control plane produces and one
    this gateway still has to resolve rather than refuse.
    """
    validator = Draft202012Validator(_schema("policy-bundle.schema.json"))
    cases = json.loads((VECTORS / "bundle.json").read_text(encoding="utf-8"))["cases"]
    worked = next(c for c in cases if c["name"] == "the contract's worked example")
    validator.validate(worked["bundle"])


def test_the_bundle_schema_refuses_what_it_says_it_refuses() -> None:
    """The refusals a schema is the right place for.

    What it cannot carry is uniqueness across a list — a duplicate policy id,
    two bindings for one endpoint — and the id grammar, which is a spelling rule
    rather than a shape. The file says as much; this pins the part it does
    carry, the arity rules below included.
    """
    validator = Draft202012Validator(_schema("policy-bundle.schema.json"))
    base = {"version": "v1", "policies": [], "bindings": [], "rejected": []}

    for bad in (
        {k: v for k, v in base.items() if k != "rejected"},
        {**base, "version": ""},
        {
            **base,
            "bindings": [{"endpoint_key": "e", "mode": "closed", "policy_ids": []}],
        },
        # `integer` rather than `number`, so the rule the description states —
        # that 1.5 is not a priority — is one the schema also enforces.
        {**base, "policies": [{"id": "x", "priority": 1.5}]},
        {**base, "policies": [{"id": "x", "priority": True}]},
        {**base, "policies": [{"id": "x", "priority": 2**53}]},
    ):
        assert not validator.is_valid(bad), bad

    # The whole float stays valid: JSON cannot tell it from the integer, so a
    # schema that refused it would refuse a bundle Rail Center can emit.
    assert validator.is_valid({**base, "policies": [{"id": "x", "priority": 1.0}]})


def test_the_bundle_schema_carries_the_binding_arity_rules() -> None:
    """`gated` names at least one policy; `open` names none.

    Both directions, because a conditional that never fires and one that always
    does are equally silent. There is deliberately no fourth state: "subject to
    nothing" is spelled `open`, and "subject to everything" is spelled by
    carrying no entry at all.
    """
    validator = Draft202012Validator(_schema("policy-bundle.schema.json"))
    base = {"version": "v1", "policies": [], "rejected": []}
    one = "5c8f1e42-0000-4000-8000-0000000000a1"

    def binding(mode: str, ids: list[str]) -> dict[str, Any]:
        return {
            **base,
            "bindings": [{"endpoint_key": "e", "mode": mode, "policy_ids": ids}],
        }

    assert validator.is_valid(binding("gated", [one]))
    assert validator.is_valid(binding("open", []))
    assert not validator.is_valid(binding("gated", []))
    assert not validator.is_valid(binding("open", [one]))


def test_the_bundle_schema_requires_what_it_says_is_required() -> None:
    """Required fields and bounds, asked rather than assumed.

    A schema whose `required` list can be emptied without a test failing is a
    schema that documents a rule and enforces nothing.
    """
    validator = Draft202012Validator(_schema("policy-bundle.schema.json"))
    base = {"version": "v1", "policies": [], "bindings": [], "rejected": []}
    one = "5c8f1e42-0000-4000-8000-0000000000a1"
    binding = {"endpoint_key": "e", "mode": "gated", "policy_ids": [one]}

    for field in ("version", "policies", "bindings", "rejected"):
        assert not validator.is_valid({k: v for k, v in base.items() if k != field}), (
            field
        )
    for field in ("endpoint_key", "mode", "policy_ids"):
        assert not validator.is_valid(
            {**base, "bindings": [{k: v for k, v in binding.items() if k != field}]}
        ), field

    # A policy needs an id whatever else it carries, and an enabled one needs a
    # priority — the rule round 4 moved under the `enabled` condition, where its
    # `required` is as easy to empty as it was before the move.
    assert not validator.is_valid({**base, "policies": [{"priority": 1}]})
    assert not validator.is_valid({**base, "policies": [{"id": one}]})
    assert not validator.is_valid({**base, "policies": [{"id": one, "enabled": True}]})
    # The negative end of the priority bound; the positive end is asserted with
    # the other type rules above. An absolute value is easy to leave out, so
    # both ends are stated somewhere.
    assert not validator.is_valid(
        {**base, "policies": [{"id": one, "priority": -(2**53)}]}
    )
    assert not validator.is_valid(
        {**base, "bindings": [{**binding, "endpoint_key": "e" * 256}]}
    )
    assert validator.is_valid(
        {**base, "bindings": [{**binding, "endpoint_key": "e" * 255}]}
    )
    # The version's bound is the same one, and for the same reason: it is held
    # for as long as the bundle is and re-echoed on every failed refresh.
    assert not validator.is_valid({**base, "version": "v" * 256})
    assert validator.is_valid({**base, "version": "v" * 255})
    # Unrecognised keys travel through here too, for the reason the ticket
    # schema gives: adding a field to the grammar must not be a flag day.
    assert validator.is_valid(
        {**base, "policies": [{"id": one, "priority": 1, "future": 1}]}
    )
    assert validator.is_valid({**base, "bindings": [{**binding, "future": 1}]})
    assert validator.is_valid({**base, "future": 1})

    # Field types the descriptions state and nothing else asked for.
    assert not validator.is_valid(
        {**base, "bindings": [{**binding, "policy_ids": [1]}]}
    )
    assert not validator.is_valid(
        {**base, "policies": [{"id": one, "priority": 1, "name": 1}]}
    )
    assert not validator.is_valid({**base, "rejected": ["not an object"]})


def test_the_bundle_schema_keeps_the_remedy_it_promises() -> None:
    """Switching a policy off has to produce a bundle this schema accepts.

    `enabled` is settled before anything is interpreted precisely so that
    disabling the offending policy is a working remedy for a bundle a reader
    cannot parse. A schema that still demanded a readable priority from a
    disabled policy would refuse exactly the bundle that remedy produces.
    """
    validator = Draft202012Validator(_schema("policy-bundle.schema.json"))
    base = {"version": "v1", "bindings": [], "rejected": []}
    one = "5c8f1e42-0000-4000-8000-0000000000a1"

    assert validator.is_valid(
        {**base, "policies": [{"id": one, "priority": "not one", "enabled": False}]}
    )
    assert validator.is_valid({**base, "policies": [{"id": one, "enabled": False}]})
    assert not validator.is_valid(
        {**base, "policies": [{"id": one, "priority": "not one"}]}
    )


def test_the_schemas_state_the_types_they_document() -> None:
    """Every `type` keyword in both schemas, asked rather than assumed.

    `required` says a field must be there and `type` says what it may be, and
    the second is the half that goes untested — a schema whose types can be
    deleted one by one without a failure documents a shape and enforces a
    presence. The count is what makes this checkable: 28 keywords, and each one
    deleted individually must fail something.
    """

    def types(node: Any) -> int:
        if isinstance(node, dict):
            return ("type" in node) + sum(types(v) for v in node.values())
        if isinstance(node, list):
            return sum(types(v) for v in node)
        return 0

    # The count, so that a `type` added without an assertion beside it fails
    # here rather than going unnoticed. Raise it when you add the assertion.
    assert types(_schema("policy-bundle.schema.json")) == 16
    assert types(_schema("x-rail-ticket.schema.json")) == 12

    bundle = Draft202012Validator(_schema("policy-bundle.schema.json"))
    base = {"version": "v1", "policies": [], "bindings": [], "rejected": []}
    one = "5c8f1e42-0000-4000-8000-0000000000a1"

    assert not bundle.is_valid({**base, "policies": "not a list"})
    assert not bundle.is_valid({**base, "bindings": {"a": 1}})
    assert not bundle.is_valid({**base, "generated_at": 42})
    assert not bundle.is_valid({**base, "policies": ["just a string"]})
    assert not bundle.is_valid(
        {**base, "policies": [{"id": one, "priority": 1, "enabled": "false"}]}
    )

    # The seven the first pass missed, each shown by a document that flips.
    assert not bundle.is_valid(["not an object"])
    assert not bundle.is_valid({**base, "version": 17})
    assert not bundle.is_valid({**base, "rejected": "none"})
    assert not bundle.is_valid({**base, "policies": [{"id": 17, "priority": 1}]})
    assert not bundle.is_valid({**base, "bindings": ["not an object"]})
    assert not bundle.is_valid(
        {**base, "bindings": [{"endpoint_key": 17, "mode": "open", "policy_ids": []}]}
    )
    assert not bundle.is_valid(
        {
            **base,
            "bindings": [{"endpoint_key": "e", "mode": "gated", "policy_ids": "abc"}],
        }
    )

    ticket = Draft202012Validator(_schema("x-rail-ticket.schema.json"))
    good = _schema("x-rail-ticket.schema.json")["examples"][0]
    assert not ticket.is_valid([good])
    for field in ("sandbox_id", "environment_fingerprint", "sandbox_type", "scored_at"):
        assert not ticket.is_valid({**good, field: 42}), field


def test_the_safe_integer_bounds_admit_the_bound_itself() -> None:
    """Both ends, and the value at each end.

    Asserting only that one past the bound is refused leaves the bound free to
    move inward, which refuses a priority and an expiry that every conformant
    reader accepts.
    """
    bundle = Draft202012Validator(_schema("policy-bundle.schema.json"))
    base = {"version": "v1", "policies": [], "bindings": [], "rejected": []}
    one = "5c8f1e42-0000-4000-8000-0000000000a1"
    safe = 2**53 - 1

    assert bundle.is_valid({**base, "policies": [{"id": one, "priority": safe}]})
    assert bundle.is_valid({**base, "policies": [{"id": one, "priority": -safe}]})
    assert bundle.is_valid({**base, "version": "v"})

    ticket = Draft202012Validator(_schema("x-rail-ticket.schema.json"))
    good = _schema("x-rail-ticket.schema.json")["examples"][0]
    assert ticket.is_valid({**good, "exp": safe})
    assert ticket.is_valid({**good, "exp": -safe})


def test_the_ticket_schema_refuses_what_its_descriptions_state() -> None:
    """The rules its prose states, asked of the schema rather than the reader.

    A schema shipped as a contract and checked only for being well-formed says
    whatever its author last typed. These are the claims its own field
    descriptions make.
    """
    validator = Draft202012Validator(_schema("x-rail-ticket.schema.json"))
    good = _schema("x-rail-ticket.schema.json")["examples"][0]

    assert validator.is_valid(good)
    # `exp` is whole seconds within what a double separates.
    assert validator.is_valid({**good, "exp": 1785529162.0})
    for bad_exp in (1785529162.5, 2**53, -(2**53), "1785529162", True, None):
        assert not validator.is_valid({**good, "exp": bad_exp}), bad_exp
    # Every field the mint writes is required; null means "not yet known".
    for field in good:
        assert not validator.is_valid({k: v for k, v in good.items() if k != field}), (
            field
        )
    assert validator.is_valid({**good, "posture_score": None, "tier": None})
    # "A number here is a score, never a string."
    assert not validator.is_valid({**good, "posture_score": "100"})
    assert not validator.is_valid({**good, "skills": "package-tracking"})
    assert not validator.is_valid({**good, "skills": [1]})
    assert not validator.is_valid({**good, "agent_id": 42})
    # `iat` is whole seconds like `exp`, and `tier` is a band name or null.
    assert not validator.is_valid({**good, "iat": 1785528262.5})
    assert not validator.is_valid({**good, "tier": 80})
    # Unrecognised keys travel through, so adding one is not a flag day.
    assert validator.is_valid({**good, "signed_by": "wave-2"})
