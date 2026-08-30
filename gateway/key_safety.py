"""What may appear in a value this gateway writes into a log line.

Every value this refuses came off the wire. A bundle's version, a policy's id
and priority, an endpoint key, a binding's mode — all are chosen by whoever
produced the bundle, never by anyone here, and this component writes them into
the messages it refuses a bundle with, which reach an operator's log. An
endpoint key travels further still, into the denial reports this gateway sends
Rail Center and whatever reads one there — and so does a caller's claimed
`x-rail-status`, which is a header rather than bundle content but is rendered
through here for the same reasons. Rail Center stores a report's `metadata`
free-form with no request-size limit in front of it, so this is the last place
either value can be bounded at all.

Four character classes are refused, by category rather than by enumeration:

* ``Cc``, control characters — a newline forges a log line and an escape
  sequence recolours one.
* ``Cf``, Unicode format characters — the zero-width set (U+200B–200D, U+FEFF)
  makes two visually identical keys different strings, and the bidi controls
  (U+202A–202E, U+2066–2069) reorder rendered text around them.
* U+2028 and U+2029, line and paragraph separator — category ``Zl`` and ``Zp``,
  so neither is caught above, and both split a line exactly like a newline.
* ``Cs``, the surrogates — a worse failure than the others rather than another
  of the same kind. ``json.loads`` reads ``"\ud800"`` into a lone surrogate,
  which is a str Python cannot encode, so writing one to a log raises
  ``UnicodeEncodeError``: the line that would have carried a forgery carries
  nothing at all, and a traceback goes up in its place.

Everything else is allowed, deliberately. An endpoint key is composed by the
control plane from a datasource slug and an endpoint name, and the name half is
close to free text — so a stricter rule here would make an endpoint that
registers cleanly impossible to report, which shows up as an endpoint nobody can
write a policy against.
"""

from __future__ import annotations

import math
import unicodedata

#: The control plane caps ``endpoint_key`` at 255, in its own schema.
MAX_ENDPOINT_KEY_LENGTH = 255

#: How long a bundle-sourced string may be before a log line truncates it. The
#: same bound as an endpoint key: past it the value is a payload, not a name.
MAX_LOGGED_LENGTH = MAX_ENDPOINT_KEY_LENGTH

#: Refused by Unicode category rather than by listing code points, so a
#: character added to one of these classes in a later Unicode revision is
#: covered without this file being edited. `re` has no `\\p{...}`, which is why
#: this is a category test and not a pattern.
_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})


def _bounded(rendered: str) -> str:
    """`rendered`, cut to `MAX_LOGGED_LENGTH` and saying where it was cut."""
    if len(rendered) <= MAX_LOGGED_LENGTH:
        return rendered
    return f"{rendered[:MAX_LOGGED_LENGTH]}…<truncated>"


def has_unsafe_key_characters(value: str) -> bool:
    """True when `value` carries a character that must not reach a log line."""
    return any(unicodedata.category(ch) in _FORBIDDEN_CATEGORIES for ch in value)


def safe_for_log(value: object) -> str:
    """`value`, rendered so that writing it into a log line is safe.

    Three guarantees, and they hold for every value JSON can carry rather than
    for strings alone. They are not claims about an arbitrary Python object: a
    class whose own name contains a newline renders that newline, because the
    name is read from the type and a type is not something the wire chooses.

    1. **It never raises**, and the guard is the last resort rather than the
       first. Two things get past every branch here: CPython refuses to render
       an integer past 4300 digits, which a bundle can carry, and a value's own
       ``__repr__`` is the value's code. It is called from log lines, including
       ones outside any ``try``, and a logging helper that can take the gateway
       down is worse than the exposure it was added to close.
    2. **It never emits an unsafe character.** Refused whole rather than
       escaped: an escape has to be undone by whoever reads it, and a value
       whose name is a bidi override is a fault to go and look at rather than
       something to read.
    3. **It is bounded**, numbers included. The reference implementation got
       that half for nothing — every JSON number is a double there, and a
       double renders in a couple of dozen characters. Python's integers are
       arbitrary-precision, so without a bound a bundle carrying a 4000-digit
       ``priority`` is refused with all 4000 digits in the message, on a path
       that runs again on every failed refresh.

    A non-string is therefore reported by its **kind**, never by its content.
    The shape is the useful half anyway: a field that should have been a string
    and arrived as an object is a contract violation to go and look at, not
    something to read in a log line.
    """
    if isinstance(value, str):
        if has_unsafe_key_characters(value):
            return "<unprintable>"
        return _bounded(value)
    if value is None:
        return "<null>"
    # `bool` before `int`, because `isinstance(True, int)` is true and a
    # boolean would otherwise render as 1 or 0. Spelled the way JSON spells it,
    # not the way Python does: an operator reading this is reading about a JSON
    # document, and `True` would have them searching a bundle for a token it
    # does not contain.
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and not math.isfinite(value):
        # `1e400` is a valid JSON number and `json.loads` reads it as infinity,
        # so this arrives off the wire. Rendering it as `inf` or `nan` would put
        # a token in the log that appears nowhere in the bundle, and the reader
        # would go looking for it.
        return "<not a finite number>"
    if isinstance(value, (int, float)):
        try:
            # Bounded like a string, and for the same reason: past this width
            # the value is a payload rather than a number worth reading. Only
            # Python's unbounded integers reach it — every float renders well
            # under it. `repr` itself raises past 4300 digits, which is a length
            # a bundle can carry, so the bound cannot be applied to its result.
            return _bounded(repr(value))
        except Exception:  # noqa: BLE001 - guarantee 1 is the whole point
            # One message for two causes, because the guard cannot tell them
            # apart and a message naming the wrong one is worse than a vague
            # one: CPython refusing a number past 4300 digits, and a value
            # whose own `__repr__` raises. Only the first is reachable from
            # JSON.
            return "<a number that could not be rendered>"
    if isinstance(value, list):
        return "<array>"
    if isinstance(value, dict):
        return "<object>"
    return f"<{type(value).__name__}>"
