"""The `1.x` condition grammar: ``{field, operator, value}``.

A condition is ``{field, operator, value}``, and the grammar it may use is
rail-center's ``docs/policy-evaluation-contract.md`` — not a local design. The
tables below are that document transcribed. Admitting a pairing it does not is a
rule this gateway enforces and Rail Center rejects; refusing one it admits is an
operator's rule turning into a 503 here and working there. Both are the
divergence the contract exists to remove, so the tables are copied rather than
derived.

**A condition outside the grammar raises rather than returning false.** The two
implementations are released separately, so Rail Center can learn a field this
gateway has not, and the natural shape — a dict lookup defaulting to False —
would silently stop enforcing a ``block`` rule, with no error, no log, and an
operator still reading the rule as live.

The operators and their type rules are `_shared`'s, which `v2` reads too —
except that `v2` reads `eq` and `ne` on a list value by value
(`v2._compare_each`) and this grammar does not; what is this grammar's own is
the field table, the derived fields and the spelling of two operators,
``present`` and ``missing``.
"""

from typing import Any, Final

from gateway.core.bundle.conditions._shared import (
    ABSENT,
    ConditionInput,
    UninterpretableCondition,
    check_operand,
    compare,
    q,
)
from gateway.core.endpoint import strip_slug

#: `v1`'s spelling of the two operators `v2` calls `existing` and `not_existing`.
_SPELLED: Final[dict[str, str]] = {"present": "existing", "missing": "not_existing"}


#: Which operators each field admits. Every pairing outside this table is
#: uninterpretable, and the asymmetries are the contract's, not conveniences:
#:
#:   * ``posture_score`` admits ``in``; ``skill_match`` does not admit ``eq``.
#:   * ``endpoint_key`` admits neither ``missing`` nor ``present`` — it is an
#:     argument to the decision rather than a claim that may be absent, so
#:     ``missing`` could never hold and ``present`` always would.
#:   * ``endpoint_key`` is the only field admitting ``matches``. A key is a
#:     structured name an operator writes rules against by family; a claim is a
#:     value the agent presents, and a pattern over an attacker-chosen claim is
#:     a subtler control than it looks. Admitting it on a claim later would be
#:     additive; withdrawing it would break rules already written.
#:
#: ``iat`` and ``exp`` are absent on purpose. Whether a ticket may be relied on
#: at all is settled when it is read, before any policy runs, and a second
#: policy-shaped way to ask the same question is a way for the two answers to
#: differ.
FIELD_OPERATORS: Final[dict[str, frozenset[str]]] = {
    "x_rail_header": frozenset({"missing", "present"}),
    "skill_match": frozenset({"missing", "present"}),
    "endpoint_key": frozenset({"eq", "ne", "in", "matches"}),
    "agent_id": frozenset({"missing", "present", "eq", "ne", "in"}),
    "sandbox_id": frozenset({"missing", "present", "eq", "ne", "in"}),
    "sandbox_type": frozenset({"missing", "present", "eq", "ne", "in"}),
    "environment_fingerprint": frozenset({"missing", "present", "eq", "ne", "in"}),
    "tier": frozenset({"missing", "present", "eq", "ne", "in"}),
    "scored_at": frozenset({"missing", "present", "eq", "ne", "in"}),
    "posture_score": frozenset(
        {"missing", "present", "eq", "ne", "lt", "lte", "gt", "gte", "in"}
    ),
    "skills": frozenset({"missing", "present", "contains"}),
}


#: The two fields derived from the endpoint being called, rather than from the
#: ticket or from the request's existence.
#:
#: A message that names no tool — `initialize`, `tools/list`, a notification —
#: has no endpoint for either to describe, so a rule keyed on one of them asks a
#: question with no subject. `decide.chain_for` drops such a rule from a keyless
#: message's chain rather than letting it resolve to absent, because absent is
#: the answer that makes ``skill_match missing`` **hold** — and a chain
#: containing "deny an agent without a matching skill" would then deny every
#: handshake, for an agent whose declared skills are exactly right, before it
#: could call anything at all.
#:
#: **Both implementations have to agree on this**, or the two sides differ on
#: precisely the messages a session opens with. The evaluation contract takes no
#: position on a call that names no endpoint; this is the position, and Rail
#: Center's evaluator needs the same one.
ENDPOINT_DERIVED_FIELDS: Final[frozenset[str]] = frozenset(
    {"endpoint_key", "skill_match"}
)


def drops_when_keyless(condition: Any) -> bool:
    """Whether `condition` asks about the endpoint being called.

    False for anything this cannot read as such a condition — a non-object, a
    non-string field, a field outside the grammar. That is deliberate: a policy
    whose condition is uninterpretable stays in the chain and refuses the
    request where the walk reaches it, exactly as it would for a call that named
    a tool. Dropping it here would turn the contract's most emphasised rule off
    for every keyless message.
    """
    return (
        isinstance(condition, dict)
        and condition.get("field") in ENDPOINT_DERIVED_FIELDS
    )


def _resolve(field: str, request: ConditionInput) -> Any:
    """What `field` resolves to for this request, or `ABSENT`.

    A claim is absent in three cases, and all three are load-bearing:

      1. **The ticket is not usable.** Every claim of an ``absent``,
         ``undecodable``, ``malformed`` or ``expired`` ticket resolves to absent,
         whatever the payload says — which is what stops an expired ticket's
         ``posture_score: 95`` outliving the ticket that carried it.
      2. **The key is not in the payload.** The ticket is unsigned, so deleting
         a key is free: a rule that only catches a null is one walked past by
         removing a line.
      3. **The key is present and null** — ``posture_score`` until scoring runs.

    A claim that is ``0``, ``""`` or ``[]`` is **present**. Testing the value's
    truth rather than its presence treats all three as missing, which is the
    likeliest drift in this function.
    """
    claims = request.ticket.token  # populated only for a `valid` ticket

    if field == "x_rail_header":
        # Folds all four unusable states into one answer, which is what makes
        # the seeded P0 a rule about trustworthy identity rather than about
        # whether a header was physically transmitted.
        return ABSENT if claims is None else "present"

    if field == "endpoint_key":
        # The contract models this as always present, since it is an argument
        # rather than a claim. A call naming no tool has no key here, and every
        # operator this field admits declines to hold against an absence — so a
        # rule written for an endpoint does not fire on a request naming none.
        return ABSENT if request.endpoint_key is None else request.endpoint_key

    if field == "skill_match":
        # List membership of the endpoint key in the ticket's `skills`. A string
        # `skills` is not a one-element list of itself and declares no skill at
        # all — the same reading `contains` takes.
        if claims is None or request.endpoint_key is None:
            return ABSENT
        skills = claims.get("skills")
        if not isinstance(skills, list):
            return ABSENT
        # **Each skill is stripped before it is compared**, exactly as a
        # binding's key is. Rail Center mints a ticket's `skills` as full keys —
        # `<slug>#<path>#<method>#<call>` — and this gateway composes no slug, so
        # comparing them whole would match nothing and turn every
        # `skill_match present` rule off.
        #
        # The cost is written down rather than designed around: stripping widens
        # what a skill covers, so an agent reaching two gateways whose data
        # sources share a full three-part key satisfies a `present` rule on the
        # one nobody declared a skill for. It needs all three conditions at once,
        # and the alternatives cost either correctness on unbound calls or the
        # slug-ignorance the rest of this design rests on.
        return (
            request.endpoint_key
            if any(
                isinstance(skill, str) and strip_slug(skill) == request.endpoint_key
                for skill in skills
            )
            else ABSENT
        )

    if claims is None or field not in claims:
        return ABSENT
    value = claims[field]
    return ABSENT if value is None else value


def holds(condition: Any, request: ConditionInput) -> bool:
    """Whether `condition` holds for this request.

    Raises `UninterpretableCondition` for a condition outside the grammar —
    never returns False for one.
    """
    if not isinstance(condition, dict):
        raise UninterpretableCondition("not an object")

    field = condition.get("field")
    operator = condition.get("operator")
    if not isinstance(field, str):
        raise UninterpretableCondition("`field` is not a string")
    if not isinstance(operator, str):
        raise UninterpretableCondition("`operator` is not a string")
    if field not in FIELD_OPERATORS:
        raise UninterpretableCondition(f"unknown field {q(field)}")
    if operator not in FIELD_OPERATORS[field]:
        raise UninterpretableCondition(
            f"field {q(field)} does not admit operator {q(operator)}"
        )

    op = _SPELLED.get(operator, operator)
    operand = condition.get("value")
    check_operand(op, operand)
    return compare(op, _resolve(field, request), operand)
