"""What every condition grammar shares: the request a condition sees, and what
each operator means once a grammar has resolved the value it asks about.

A grammar — `v1` or `v2` — reads a condition's own shape and resolves the value
it names; the operators, their operands and their type rules are one
vocabulary across both, because they are what Rail Center's evaluator and this
gateway must agree on byte for byte whichever shape a bundle carries — except
`eq` and `ne` on a list value, which `v2` reads value by value
(`v2._compare_each`) and `v1` leaves to `compare`, unchanged.

Three things differ from the TypeScript this was ported from, and every one of
them is a way for the two implementations to disagree:

  * **A bool is an int in Python.** ``isinstance(True, int)`` is true here and
    ``typeof true === "boolean"`` there, so every scalar test below excludes
    bools explicitly.

  * **Python integers are arbitrary-precision; the contract's numbers are
    doubles.** Every number reaching a comparison is narrowed by `double`, on
    both sides of it.

  * **`float()` raises where JavaScript saturates.** ``float(10**400)`` is an
    ``OverflowError``, not ``inf``, so `double` catches it and saturates the
    way the contract requires.
"""

import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from gateway.core.key_safety import safe_for_log
from gateway.core.ticket import ParseResult

#: Every operator, in `v2`'s spelling; `v1` spells the first two `present` and
#: `missing`. Which operand each takes is `check_operand`'s; which value each
#: can hold against is `compare`'s.
OPERATORS: Final[frozenset[str]] = frozenset(
    {
        "existing",
        "not_existing",
        "eq",
        "ne",
        "lt",
        "lte",
        "gt",
        "gte",
        "in",
        "contains",
        "not_contains",
        "matches",
    }
)


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


def q(value: object) -> str:
    """A condition's own text, safe to put in a message.

    These messages are built from `path` and `op` — bundle content — and
    reach the refusal log line on every request that touches the rule.
    Sanitising where the message is *built* rather than where it is printed
    keeps every consumer of it safe, including ones added later.
    """
    return f"`{safe_for_log(value)}`"


@dataclass(frozen=True)
class ConditionInput:
    """The request, as a condition sees it."""

    #: How the ``x-rail`` header read. Only a ``valid`` ticket carries claims.
    ticket: ParseResult
    #: The resolved endpoint key, or None when the call named none.
    endpoint_key: str | None
    #: The request's headers, names lowercased; a repeated header is a list.
    headers: Mapping[str, str | list[str]] = field(default_factory=dict)


def request_headers(pairs: list[tuple[str, str]]) -> dict[str, str | list[str]]:
    """`request.headers` from `(name, value)` pairs as received.

    Names are lowercased, since HTTP's are case-insensitive. **Every value is
    split on commas**, whitespace trimmed, and the parts of every line of one
    name are pooled in the order received: a header with one value is that
    string, and one with several is the list of them. Apigee splits on commas
    before the callout sees a header, and a line it delivers cannot be told
    from two, so splitting here is what gives both hosts the same value — and
    what makes ``X-Tenant: acme, evil`` and two ``X-Tenant`` lines the same
    request to a rule.
    """
    grouped: dict[str, list[str]] = {}
    for name, value in pairs:
        grouped.setdefault(name.lower(), []).extend(
            part.strip() for part in value.split(",")
        )
    return {name: v[0] if len(v) == 1 else v for name, v in grouped.items()}


class _Absent:
    """The absence of a value. A singleton, compared with ``is``.

    A sentinel rather than ``None``, because ``None`` is a value a claim can
    hold on the wire, and the contract requires that case to resolve to absent
    by the same door as a missing key, not by being indistinguishable from one.
    """

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<absent>"


ABSENT: Final = _Absent()


def is_scalar(value: object) -> bool:
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


def is_number(value: object) -> bool:
    """A number the ordered operators may compare. Bools are not numbers."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def double(value: Any) -> Any:
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


def scalar_equals(left: object, right: object) -> bool:
    """Same kind and same value, once both numbers are doubles.

    ``"40"`` does not equal ``40`` and ``""`` does not equal ``0``: a string is
    never a number, whatever either could be read as.
    """
    if not (is_scalar(left) and is_scalar(right)):
        return False
    narrowed_left, narrowed_right = double(left), double(right)
    # A str and a float are never equal in Python, so the kind check the
    # contract requires is the comparison itself once both sides are narrowed.
    return bool(narrowed_left == narrowed_right)


def glob_matches(pattern: str, key: str) -> bool:
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


def check_operand(op: str, value: Any) -> None:
    """The operand shape each operator requires.

    A ``lt`` against a string operand is not a rule that is false — it is one
    that can never be true, which is the failure an operator is least likely to
    notice.
    """

    def refuse(want: str) -> None:
        raise UninterpretableCondition(f"op {q(op)} needs {want} as its operand")

    if op in ("existing", "not_existing"):
        return  # Takes none. Supplying one is not an error.
    if op in ("eq", "ne", "contains", "not_contains"):
        if not is_scalar(value):
            refuse("a string or a number")
        return
    if op in ("lt", "lte", "gt", "gte"):
        if not is_number(value):
            refuse("a number")
        return
    if op == "in":
        if not isinstance(value, list):
            refuse("a list")
        return
    # `matches`, the last operator `OPERATORS` admits.
    if not isinstance(value, str):
        refuse("a string")


def compare(op: str, resolved: Any, operand: Any) -> bool:
    """Whether `op` holds for the value a grammar resolved, `ABSENT` included.

    The operand has passed `check_operand`.
    """
    if op == "existing":
        return resolved is not ABSENT
    if op == "not_existing":
        return resolved is ABSENT

    # `ne` does not hold for an absent value. A rule meaning "absent or
    # different" is two conditions, and writing it as two is clearer than having
    # `ne` quietly mean both.
    if resolved is ABSENT:
        return False

    claim = resolved
    if op == "eq":
        return scalar_equals(claim, operand)
    if op == "ne":
        return (
            is_scalar(claim)
            and is_scalar(operand)
            and not scalar_equals(claim, operand)
        )
    if op in ("lt", "lte", "gt", "gte"):
        if not is_number(claim):
            return False
        left, right = double(claim), double(operand)
        if op == "lt":
            return bool(left < right)
        if op == "lte":
            return bool(left <= right)
        if op == "gt":
            return bool(left > right)
        return bool(left >= right)
    if op == "in":
        # A non-scalar element is accepted by `check_operand` and simply never
        # matches, so no comparison ever sees two containers.
        return any(scalar_equals(claim, item) for item in operand)
    if op == "not_contains":
        # Its own operator rather than a negated `contains`, so that it declines
        # where `contains` does — on an absent value and on one that is not a
        # list — instead of holding there.
        return isinstance(claim, list) and not any(
            scalar_equals(item, operand) for item in claim
        )
    if op == "contains":
        # The claim is the list here. Reaching for `operand in claim` would
        # substring-match a string claim, so a value of
        # `"finretail.administrator"` would satisfy a rule about
        # `"finretail.admin"`.
        return isinstance(claim, list) and any(
            scalar_equals(item, operand) for item in claim
        )
    # `matches`, the last operator left once every branch above has returned.
    return isinstance(claim, str) and glob_matches(operand, claim)
