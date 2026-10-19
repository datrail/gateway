"""The `2.x` condition grammar: ``{path, op, value}``.

**The path is data**: its first segment names one of the two sources this
gateway builds, and the rest is walked through that source's JSON one key at a
time. No claim, header or field name is known here; Rail Center validates a
path against the shapes it publishes before a bundle carrying it goes out, and
this module answers for whatever arrives.

The sources:

  * ``ticket`` — the decoded ``x-rail`` ticket, **only when it is usable**. A
    ticket that is absent, undecodable, malformed or expired has no claims
    here, so every ``ticket.*`` path reads absent. Such a request is normally
    decided by the bundle's ``ticket_fallback`` before any condition runs.
  * ``request`` — ``{"endpoint_key": ..., "headers": {...}}``. The key is the
    resolved ``<path>#<method>#<call>``, absent for a message naming no tool.
    Header names are lowercased and values split on commas: a header with one
    value is that string, one with several is the list of them.

On a list, ``eq`` holds when every value equals the operand, ``ne`` when any
value differs, and ``in`` and ``matches`` when any value does; ``contains`` and
``not_contains`` ask whether one value equals it.

**A condition outside the grammar raises rather than returning false** — an
unknown source, an unknown operator, an operand of the wrong shape. The two
implementations are released separately, and the natural shape — a lookup
defaulting to False — would silently stop enforcing a ``block`` rule.
"""

from typing import Any, Final

from gateway.core.bundle.conditions._shared import (
    ABSENT,
    OPERATORS,
    ConditionInput,
    UninterpretableCondition,
    check_operand,
    compare,
    glob_matches,
    q,
    scalar_equals,
)

#: The roots a path may start from. The only names this module knows, because
#: building a source is the one thing a ruleset cannot describe.
SOURCES: Final[frozenset[str]] = frozenset({"ticket", "request"})


def _source(name: str, request: ConditionInput) -> Any:
    """The JSON a path's first segment names, or `ABSENT`."""
    if name == "ticket":
        # Populated only for a `valid` ticket, which is what stops an expired
        # ticket's score outliving the ticket that carried it.
        token = request.ticket.token
        return ABSENT if token is None else token
    return {
        **(
            {"endpoint_key": request.endpoint_key}
            if request.endpoint_key is not None
            else {}
        ),
        "headers": dict(request.headers),
    }


def _walk(value: Any, keys: list[str]) -> Any:
    """The value `keys` name inside `value`, or `ABSENT`.

    One key at a time. **A missing step reads as absent**, and so does one that
    is null or is not an object at all: ``posture: 5`` has no ``overall`` any
    more than a ticket with no ``posture`` does. Raising instead would turn an
    unsigned ticket's shape into a 503 its sender chooses, and reading through
    a list or a string would give an index a meaning the contract never gave
    it. A top-level key spelled ``"posture.overall.score"`` is a key nothing
    reads.

    A claim that is ``0``, ``""`` or ``[]`` is **present**. Testing the value's
    truth rather than its presence treats all three as missing, which is the
    likeliest drift in this function.
    """
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            return ABSENT
        value = value[key]
    return ABSENT if value is None else value


def drops_when_keyless(condition: Any) -> bool:
    """Never: a message naming no tool faces the whole chain, and a rule on
    ``request.endpoint_key`` reads the key as absent there."""
    return False


def holds(condition: Any, request: ConditionInput) -> bool:
    """Whether `condition` holds for this request.

    Raises `UninterpretableCondition` for a condition outside the grammar —
    never returns False for one.
    """
    if not isinstance(condition, dict):
        raise UninterpretableCondition("not an object")

    # Unrecognised keys travel through untouched. They change no decision on
    # either side, and refusing them would make adding one a flag day across
    # two independently released implementations.
    path = condition.get("path")
    op = condition.get("op")
    if not isinstance(path, str):
        raise UninterpretableCondition("`path` is not a string")
    if not isinstance(op, str):
        raise UninterpretableCondition("`op` is not a string")
    root, *keys = path.split(".")
    if root not in SOURCES:
        raise UninterpretableCondition(f"unknown source in path {q(path)}")
    if op not in OPERATORS:
        raise UninterpretableCondition(f"unknown op {q(op)}")

    operand = condition.get("value")
    check_operand(op, operand)

    resolved = _walk(_source(root, request), keys)
    if op in ("eq", "ne", "in", "matches") and isinstance(resolved, list):
        return _compare_each(op, resolved, operand)
    return compare(op, resolved, operand)


def _compare_each(op: str, values: list[Any], operand: Any) -> bool:
    """`eq`, `ne`, `in` and `matches` on a list, read value by value.

    **`ne` holds when any value differs**, and `eq`, its mirror, when every
    value equals the operand. That is what keeps the one allowlist a policy can
    write — block on `ne "acme"`, block on `not_existing` — closed against a
    repeated header: ``acme, evil`` has a value that is not ``acme``. The other
    reading, `ne` holding only where no value equals, would admit any value
    sent beside ``acme``.

    A value that is not a scalar — a bool, an object, a list — never equals
    the operand, so it counts as a value that differs: ``[true]`` satisfies
    `ne` and not `eq`, where a scalar claim of ``true`` satisfies neither. For
    a `block` rule that reading fails closed.

    **`in` and `matches` hold when any value does** — the reading a denylist
    needs, as `ne`'s is the one an allowlist needs: ``matches "*sqlmap*"``
    refuses ``sqlmap/1.7, x`` as it refuses ``sqlmap/1.7``, and a User-Agent
    whose own comma splits it still matches ``*Chrome*``. A value that is not
    a string never matches a pattern, and one that is not a scalar is a member
    of nothing.

    An empty list has no value to differ, equal or match, so none holds.
    """
    if not values:
        return False
    if op == "ne":
        return any(not scalar_equals(value, operand) for value in values)
    if op == "in":
        return any(scalar_equals(value, item) for value in values for item in operand)
    if op == "matches":
        return any(
            isinstance(value, str) and glob_matches(operand, value) for value in values
        )
    return all(scalar_equals(value, operand) for value in values)
