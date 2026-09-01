"""Policy ids, in the one spelling everything compares against.

Three places in the evaluation contract need this and must agree: the ordering
tiebreak, the membership test a binding does against the chain, and the id a
decision reports on its denial. Three separate normalisations would be three
chances to drift, so there is one.

The contract names five spellings that must all parse, in any mixture of case::

    55550000-0000-4000-8000-0000000000aa            canonical
    55550000-0000-4000-8000-0000000000AA            uppercase hex
    {55550000-0000-4000-8000-0000000000aa}          braced
    urn:uuid:55550000-0000-4000-8000-0000000000aa   URN
    555500000000400080000000000000aa                undashed

Rail Center emits the canonical form, so the other four arise only in a bundle
assembled elsewhere — which is the case the tiebreak exists for. Refusing them
is not the safe direction: an id the contract says must parse makes the bundle
unusable if it does not, and an unusable bundle refuses traffic. A hand-rolled
``^[0-9a-f]{8}-…$`` accepts the first two and turns the other three into an
outage of enforcement where Rail Center enforces normally.

**Whitespace is not trimmed**, unlike the TypeScript gateway being replaced,
which called `.trim()` first. Rail Center refuses a padded id — its
`canonical_id` is `str(uuid.UUID(str(id)))`, which raises on one — so accepting
it here would admit a bundle the control plane calls unusable.

Where the contract is silent, this file's behaviour follows from the code below
and not from any rule stated about it. Three attempts to state one were each
falsified by the code, and a fourth said the vectors carried something they did
not. `tests/vectors/bundle.json` is what settles a spelling; that file and this
function are the whole of the answer.

Two disagreements are worth naming here because they point opposite ways.
`uuid.UUID` strips its `urn:` prefix case-sensitively, so Rail Center refuses
`URN:UUID:` in upper case and this file accepts it, the contract having said
all five spellings parse in any mixture of case. And Rail Center is far more
permissive than the contract elsewhere: doubled braces, a single unbalanced
brace, an interior `uuid:`, an underscore in place of a digit, a leading plus
and non-ASCII digits all parse there and none of them here. A minus is the one
that does not, and only when it stands in for a digit: `uuid.UUID` strips
hyphens, so `-` and 31 digits leaves 31 and raises, while `-` in front of a
whole 32-digit id leaves the id and parses in all three.

The two languages do not even agree on what whitespace is: Python's `strip`
removes U+001C–U+001F and U+0085, which JavaScript's `trim` does not, and
`trim` removes U+FEFF, which `strip` does not. Trimming would therefore give
three implementations three answers rather than two.
"""

from __future__ import annotations

import re

#: RFC 4122 §3, and the only prefix the URN form carries. Matched
#: case-insensitively, like every other part of the spelling.
URN_PREFIX = "urn:uuid:"

#: A UUID is 128 bits, which is 32 hex digits. Not a tunable — the width of the
#: type.
HEX_DIGITS = 32

#: The canonical text form's group boundaries, 8-4-4-4-12.
_GROUP_ENDS = (8, 12, 16, 20)

#: ASCII hex only. `str.isalnum` and `int(x, 16)` both admit more than this —
#: Arabic-Indic digits for the first, a leading sign and underscores for the
#: second — and each would make one implementation read an id the other cannot.
#:
#: Unanchored, and matched with `fullmatch` at the one place it is used. An
#: anchor in the pattern as well would be a second rule saying the same thing,
#: and the two would have to be kept in step for no gain.
_HEX_ONLY = re.compile(r"[0-9a-fA-F]+")


def canonical_uuid(value: object) -> str | None:
    """The canonical lowercase-hyphenated form of `value`, or ``None``.

    ``None`` is a refusal the caller has to act on, not a value to compare: an
    id that cannot be compared cannot be matched against a chain, so a bundle
    carrying one is unusable and refuses traffic as a whole.
    """
    if not isinstance(value, str):
        return None

    body = value

    if body.startswith("{") and body.endswith("}"):
        body = body[1:-1]
    # Anchored at the front, and lowercased. `URN_PREFIX in body.lower()` is
    # indistinguishable in behaviour — a prefix found anywhere else leaves a
    # colon among the digits and the alphabet check refuses it either way — but
    # the rule is that the URN form *begins* with it, and a search says
    # something the contract does not. Dropping the `.lower()` is a real
    # change, and the contract's "any combination of case" is what forbids it.
    if body[: len(URN_PREFIX)].lower() == URN_PREFIX:
        body = body[len(URN_PREFIX) :]

    # Hyphens are stripped rather than checked by position, because the
    # undashed spelling carries none and the canonical one carries four. What
    # has to hold either way is the digit count and the alphabet, and checking
    # those after stripping accepts both without a branch per spelling.
    hex_digits = body.replace("-", "")
    if len(hex_digits) != HEX_DIGITS or not _HEX_ONLY.fullmatch(hex_digits):
        return None

    lower = hex_digits.lower()
    parts, cut = [], 0
    for end in _GROUP_ENDS:
        parts.append(lower[cut:end])
        cut = end
    parts.append(lower[cut:])
    return "-".join(parts)
