"""Whether one policy condition holds for one request.

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

Four things differ from the TypeScript this is ported from, and every one of
them is a way for the two implementations to disagree:

  * **A bool is an int in Python.** ``isinstance(True, int)`` is true here and
    ``typeof true === "boolean"`` there, so every scalar test below excludes
    bools explicitly. The contract's reason for excluding them is that
    ``True == 1`` in Python and ``true === 1`` is false in TypeScript, which
    would make a rule's meaning depend on which language read it.

  * **Python integers are arbitrary-precision; the contract's numbers are
    doubles.** ``2**53`` and ``2**53 + 1`` are distinct integers here and the
    same double in JavaScript, so comparing them unnarrowed answers differently
    on the two sides. Every number reaching a comparison is narrowed by
    `_double`, on both sides of it — narrowing only the claim leaves the same
    divergence on the operand.

  * **`float()` raises where JavaScript saturates.** ``float(10**400)`` is an
    ``OverflowError``, not ``inf``. An exception where a comparison belongs is
    neither an allow nor a deny, so `_double` catches it and saturates the way
    the contract requires.

  * **Python has no prototype chain, so the reference's `own()` guard is
    deliberately not ported.** In JavaScript a plain-object lookup reaches
    ``Object.prototype``, so a condition naming ``__proto__`` resolves to
    something inherited and then throws. A ``dict`` lookup here reaches nothing
    it did not store, and the field name is checked against `FIELD_OPERATORS`
    before any claim is read regardless. A guard that guards nothing is worse
    than none: the next reader takes it for a rule and looks for the hazard it
    answers.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Final

from gateway.key_safety import safe_for_log
from gateway.ticket import ParseResult


class UninterpretableCondition(Exception):
    """A condition this gateway cannot interpret.

    Raised where the walk reaches it, so an earlier policy that already denied
    still gives that request a clean answer. The caller answers 503 and reports
    no denial: no policy decided the request, so naming one would attribute a
    verdict nobody reached.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(f"uninterpretable condition: {reason}")
        self.reason = reason
        #: The policy whose condition could not be read. Attached by the walk
        #: rather than passed in here, because `holds` is handed a condition
        #: and never the policy carrying it — and the contract requires the
        #: refusal to be logged "naming the offending policy where there is
        #: one", disabling that policy being the remedy it names. None only
        #: where something outside the walk raised this.
        self.policy_id: str | None = None


def _q(value: object) -> str:
    """A condition's own text, safe to put in a message.

    These messages are built from `field` and `operator` — bundle content — and
    reach the refusal log line on every request that touches the rule.
    Sanitising where the message is *built* rather than where it is printed
    keeps every consumer of it safe, including ones added later.
    """
    return f"`{safe_for_log(value)}`"


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


def keys_on_endpoint(condition: Any) -> bool:
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


@dataclass(frozen=True)
class ConditionInput:
    """The request, as a condition sees it."""

    #: How the ``x-rail`` header read. Only a ``valid`` ticket carries claims.
    ticket: ParseResult
    #: The resolved endpoint key, or None when the call named none.
    endpoint_key: str | None


class _Absent:
    """The absence of a claim. A singleton, compared with ``is``.

    A sentinel rather than ``None``, because ``None`` is a value a claim can
    legitimately hold — ``posture_score`` is null for an agent registered but
    not yet scored — and the contract requires that case to resolve to absent
    by the same door as a missing key, not by being indistinguishable from one.
    """

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<absent>"


_ABSENT: Final = _Absent()


def _is_scalar(value: object) -> bool:
    """**No coercion, in either direction**, so only these kinds ever compare.

    Bools are excluded because ``True == 1`` in Python and ``true === 1`` is
    false in TypeScript; lists and objects because ``[] == 0`` and ``[""] == ""``
    are true in JavaScript and false in a language that does not coerce. Either
    would make a rule's meaning depend on which equality an implementer reached
    for.

    Note what this means for ``ne``: a boolean claim does **not** satisfy it.
    Not comparing is not the same as comparing unequal.
    """
    return isinstance(value, (str, int, float)) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    """A number the ordered operators may compare. Bools are not numbers."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _double(value: Any) -> Any:
    """A number as an IEEE-754 double; anything else unchanged.

    The contract's numbers are doubles on both sides of every comparison.
    Python's integers are not bounded, so two values a double cannot tell apart
    stay distinct here and compare equal in JavaScript — ``2**53`` against
    ``2**53 + 1``, and every pair of over-large integers that saturate to the
    same infinity.

    ``float()`` raising rather than saturating is the part that has to be
    written out: ``float(10**400)`` is an ``OverflowError``, and an exception
    where a comparison belongs is neither an allow nor a deny.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        return value
    try:
        return float(value)
    except OverflowError:
        return math.inf if value > 0 else -math.inf


def _scalar_equals(left: object, right: object) -> bool:
    """Same kind and same value, once both numbers are doubles.

    ``"40"`` does not equal ``40`` and ``""`` does not equal ``0``: a string is
    never a number, whatever either could be read as.
    """
    if not (_is_scalar(left) and _is_scalar(right)):
        return False
    narrowed_left, narrowed_right = _double(left), _double(right)
    # A str and a float are never equal in Python, so the kind check the
    # contract requires is the comparison itself once both sides are narrowed.
    return bool(narrowed_left == narrowed_right)


def _glob_matches(pattern: str, key: str) -> bool:
    """A glob with **exactly one metacharacter**: ``*``.

    It stands for any run of characters, including an empty one, including the
    ``.`` that separates endpoint-key segments, and including a newline. The
    match is anchored at both ends.

    One metacharacter is the largest grammar with nothing left to disagree
    about, and that is the design rather than an omission. **`fnmatch` is not
    used and must not be**: it supports ``[seq]`` and ``[!seq]``, and on some
    platforms it folds case — three ways for this to answer differently from an
    implementation that has no glob library at all and reaches for a regex.

    Scanning rather than translating to a regex, because a conformant
    translation needs three things at once that engines get wrong by default:
    every character but ``*`` escaped, whole-key anchoring spelled the way that
    engine spells it, and ``*`` matching a newline where ``.`` does not without
    ``re.DOTALL``. The scan needs none of them and cannot backtrack.

    Comparison is exact: no case folding and no Unicode normalisation. ``é`` as
    one code point and as ``e`` plus a combining acute are different keys here,
    which keeps a rule's reach from depending on which form an operator's editor
    saved.
    """
    parts = pattern.split("*")

    # No `*` at all is a literal, matching exactly what `eq` would. Accepted
    # rather than refused: it can fire, and refusing it would mean broadening a
    # rule from `finretail.orders` to `finretail.*` had to change the operator.
    if len(parts) == 1:
        return key == pattern

    first, last = parts[0], parts[-1]
    if not key.startswith(first) or not key.endswith(last):
        return False

    # **The two ends must not overlap.** `ab*ab` does not match `ab`, though the
    # key both starts and ends with `ab`: `*` stands for a run of characters,
    # possibly empty, but never for characters counted twice. An implementation
    # checking only startswith-and-endswith matches here where a conformant one
    # does not, and that is the natural shape to write.
    limit = len(key) - len(last)
    if len(first) > limit:
        return False

    # Interior segments match at their earliest position, left to right. With
    # `*` the only metacharacter every segment between two stars is a fixed
    # literal, so taking one early never rules out a match a fuller search would
    # have found — which is why no backtracking is needed to be correct.
    cursor = len(first)
    for segment in parts[1:-1]:
        if not segment:
            continue  # `a**b` is `a*b`
        at = key.find(segment, cursor)
        if at < 0 or at + len(segment) > limit:
            return False
        cursor = at + len(segment)
    return True


def _resolve(field: str, request: ConditionInput) -> Any:
    """What `field` resolves to for this request, or `_ABSENT`.

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
        return _ABSENT if claims is None else "present"

    if field == "endpoint_key":
        # The contract models this as always present, since it is an argument
        # rather than a claim. A call naming no tool has no key here, and every
        # operator this field admits declines to hold against an absence — so a
        # rule written for an endpoint does not fire on a request naming none.
        return _ABSENT if request.endpoint_key is None else request.endpoint_key

    if field == "skill_match":
        # List membership of the endpoint key in the ticket's `skills`. A string
        # `skills` is not a one-element list of itself and declares no skill at
        # all — the same reading `contains` takes.
        if claims is None or request.endpoint_key is None:
            return _ABSENT
        skills = claims.get("skills")
        if not isinstance(skills, list):
            return _ABSENT
        return (
            request.endpoint_key
            if any(skill == request.endpoint_key for skill in skills)
            else _ABSENT
        )

    if claims is None or field not in claims:
        return _ABSENT
    value = claims[field]
    return _ABSENT if value is None else value


def _check_operand(operator: str, value: Any) -> None:
    """The operand shape each operator requires.

    A ``lt`` against a string operand is not a rule that is false — it is one
    that can never be true, which is the failure an operator is least likely to
    notice.
    """

    def refuse(want: str) -> None:
        raise UninterpretableCondition(
            f"operator {_q(operator)} needs {want} as its operand"
        )

    if operator in ("missing", "present"):
        return  # Takes none. Supplying one is not an error.
    if operator in ("eq", "ne", "contains"):
        if not _is_scalar(value):
            refuse("a string or a number")
        return
    if operator in ("lt", "lte", "gt", "gte"):
        if not _is_number(value):
            refuse("a number")
        return
    if operator == "in":
        if not isinstance(value, list):
            refuse("a list")
        return
    if operator == "matches":
        # Refused at validation rather than treated as a pattern that never
        # matches: `matches` compares against the endpoint key, which is always
        # a string, so a non-string pattern is a rule that can never hold.
        if not isinstance(value, str):
            refuse("a string")
        return
    raise UninterpretableCondition(f"unknown operator {_q(operator)}")


def holds(condition: Any, request: ConditionInput) -> bool:
    """Whether `condition` holds for this request.

    Raises `UninterpretableCondition` for a condition outside the grammar —
    never returns False for one.
    """
    if not isinstance(condition, dict):
        raise UninterpretableCondition("not an object")

    # Unrecognised keys travel through untouched. They change no decision on
    # either side, and refusing them would make adding a field to the grammar a
    # flag day across two independently released implementations.
    field = condition.get("field")
    operator = condition.get("operator")
    if not isinstance(field, str):
        raise UninterpretableCondition("`field` is not a string")
    if not isinstance(operator, str):
        raise UninterpretableCondition("`operator` is not a string")
    if field not in FIELD_OPERATORS:
        raise UninterpretableCondition(f"unknown field {_q(field)}")
    if operator not in FIELD_OPERATORS[field]:
        raise UninterpretableCondition(
            f"field {_q(field)} does not admit operator {_q(operator)}"
        )

    operand = condition.get("value")
    _check_operand(operator, operand)

    resolved = _resolve(field, request)
    if operator == "missing":
        return resolved is _ABSENT
    if operator == "present":
        return resolved is not _ABSENT

    # `ne` does not hold for an absent field. A rule meaning "absent or
    # different" is two conditions, and writing it as two is clearer than having
    # `ne` quietly mean both.
    if resolved is _ABSENT:
        return False

    claim = resolved
    if operator == "eq":
        return _scalar_equals(claim, operand)
    if operator == "ne":
        return (
            _is_scalar(claim)
            and _is_scalar(operand)
            and not _scalar_equals(claim, operand)
        )
    if operator in ("lt", "lte", "gt", "gte"):
        if not _is_number(claim):
            return False
        left, right = _double(claim), _double(operand)
        if operator == "lt":
            return bool(left < right)
        if operator == "lte":
            return bool(left <= right)
        if operator == "gt":
            return bool(left > right)
        return bool(left >= right)
    if operator == "in":
        # The operand is a list and each element is compared against the claim.
        # A non-scalar element is accepted by `_check_operand` and simply never
        # matches, so no comparison ever sees two containers.
        return any(_scalar_equals(claim, item) for item in operand)
    if operator == "contains":
        # The claim is the list here. Reaching for `operand in claim` would
        # substring-match a string claim, so `skills` of
        # `"finretail.administrator"` would satisfy a rule about
        # `"finretail.admin"`.
        return isinstance(claim, list) and any(
            _scalar_equals(item, operand) for item in claim
        )
    # `matches` — the last operator the field table admits, and the only one
    # left once every branch above has returned.
    return isinstance(claim, str) and _glob_matches(operand, claim)
