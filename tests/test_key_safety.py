"""What reaches an operator's log, for values the vectors cannot carry.

The bundle vectors exercise `safe_for_log` through refusal messages, which is
the path that matters, but a JSON file can only hand it the types JSON has.
Its three guarantees — it never raises, never emits an unsafe character, and is
bounded — hold for every value JSON can carry, and the ones most likely to break
are the values JSON cannot spell.
"""

from __future__ import annotations

import pytest

from gateway.key_safety import (
    MAX_ENDPOINT_KEY_LENGTH,
    MAX_LOGGED_LENGTH,
    has_unsafe_key_characters,
    safe_for_log,
)


class Exploding:
    """A value whose every dunder raises, which is what a helper must survive."""

    def __repr__(self) -> str:
        raise RuntimeError("repr")

    def __str__(self) -> str:
        raise RuntimeError("str")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("ordinary", "ordinary"),
        ("", ""),
        (None, "<null>"),
        (True, "true"),
        (False, "false"),
        (0, "0"),
        (-1, "-1"),
        (1.5, "1.5"),
        # `1e400` is a valid JSON number that `json.loads` reads as infinity, so
        # this arrives off the wire rather than from a bug. Rendering it as
        # `inf` would put a token in the log that appears in no bundle.
        (float("inf"), "<not a finite number>"),
        (float("-inf"), "<not a finite number>"),
        (float("nan"), "<not a finite number>"),
        ([1, 2], "<array>"),
        ({"a": 1}, "<object>"),
        (b"bytes", "<bytes>"),
        ({1, 2}, "<set>"),
    ],
)
def test_a_value_renders_by_kind_when_it_is_not_a_string(
    value: object, expected: str
) -> None:
    """`true` and `false` rather than Python's `True` and `False`.

    An operator reading a log line is reading about a JSON document, and JSON
    spells its booleans in lower case. Rendering Python's spelling would have
    them searching a bundle for a token it does not contain.
    """
    assert safe_for_log(value) == expected


def test_it_never_raises_on_a_value_that_raises() -> None:
    """It is called from log lines, including ones outside any try.

    A logging helper that can take the gateway down is worse than the exposure
    it was added to close, so a value is reported by its type — which is read
    from the class, never from the value.
    """
    assert safe_for_log(Exploding()) == "<Exploding>"


@pytest.mark.parametrize(
    "value",
    [
        # Written as escapes rather than as the characters themselves. Ruff
        # refuses an invisible literal in source for the same reason this
        # function refuses one in a log line: nobody reviewing it can see it.
        "line\nbreak",
        "carriage\rreturn",
        "tab\tstop",
        "escape\x1b[31m",
        "null\x00byte",
        "zero\u200bwidth",
        "bidi\u202eoverride",
        "isolate\u2066override",
        "line\u2028separator",
        "paragraph\u2029separator",
        "byte\ufefforder mark",
        # Category Cs, and a worse failure than the rest: this is a str Python
        # cannot encode, so writing it to a log raises rather than forging a
        # line. `json.loads('"\\ud800"')` produces exactly this.
        "lone\ud800surrogate",
    ],
)
def test_an_unsafe_string_is_refused_whole(value: str) -> None:
    """Refused rather than escaped.

    Escaping would have to be reversed by whoever reads it, and a partial
    escape is the failure this exists to prevent. The value's *shape* is the
    useful half anyway: a name carrying a bidi override is a fault to go and
    look at, not something to read.
    """
    assert has_unsafe_key_characters(value)
    assert safe_for_log(value) == "<unprintable>"


def test_the_bound_is_the_one_an_endpoint_key_has() -> None:
    """Stated as a literal, so changing either constant fails here.

    The truncation tests build their inputs from `MAX_LOGGED_LENGTH`, so they
    hold for any value of it and pin none. The value is the claim: the control plane
    caps an endpoint key at 255, and past that a bundle-sourced string is a
    payload rather than a name.
    """
    assert MAX_ENDPOINT_KEY_LENGTH == 255
    assert MAX_LOGGED_LENGTH == MAX_ENDPOINT_KEY_LENGTH


def test_a_surrogate_pair_is_ordinary_text() -> None:
    """Refusing Cs must not refuse an emoji.

    A JSON escape pair — `"\\ud83d\\ude00"` — decodes to one code point in
    category So, not to two surrogates, so nothing legitimate is caught by the
    rule above.
    """
    import json

    decoded = json.loads('"\\ud83d\\ude00"')
    assert not has_unsafe_key_characters(decoded)
    assert safe_for_log(decoded) == decoded


def test_a_number_too_long_to_read_is_bounded_like_a_string() -> None:
    """Python's integers are unbounded and JSON's numbers are not.

    The reference implementation got this for nothing, since every JSON number
    there is a double. Here a bundle carrying a four-thousand-digit priority
    would otherwise put all four thousand digits in a refusal, on a path that
    runs again on every failed refresh.
    """
    rendered = safe_for_log(int("9" * 4000))
    assert rendered.endswith("…<truncated>")
    assert len(rendered) == MAX_LOGGED_LENGTH + len("…<truncated>")


def test_every_float_renders_well_under_the_bound() -> None:
    """The claim the number branch's comment makes, over the extremes."""
    for value in (0.0, -0.0, 1e308, -1e308, 5e-324, 1.7976931348623157e308, 1 / 3):
        assert len(safe_for_log(value)) < MAX_LOGGED_LENGTH


def test_a_number_cpython_will_not_render_does_not_take_the_process_down() -> None:
    """The one place guarantee 1 is not free.

    CPython refuses to render an integer past 4300 digits, and a bundle can
    carry one — `10 ** 4400` is a JSON number. `repr` raises there, so the
    bound cannot be applied to its result and the call has to be guarded.
    """
    assert safe_for_log(10**4400) == "<a number that could not be rendered>"


def test_a_value_whose_repr_raises_is_reported_rather_than_propagated() -> None:
    """`Exploding` never reaches a `repr` call; an int subclass does.

    The kind branches read the type, which cannot raise. The number branch
    reads the value, which can — and this one is five, so the message must not
    claim the number was too long. The guard cannot tell the two causes apart,
    which is why it names neither.
    """

    class BadInt(int):
        def __repr__(self) -> str:
            raise RuntimeError("boom")

    assert safe_for_log(BadInt(5)) == "<a number that could not be rendered>"


def test_a_long_string_is_truncated_and_says_so() -> None:
    rendered = safe_for_log("x" * (MAX_LOGGED_LENGTH + 1))
    assert rendered.endswith("…<truncated>")
    assert rendered.startswith("x" * MAX_LOGGED_LENGTH)


def test_a_string_of_exactly_the_bound_is_not_truncated() -> None:
    at_the_bound = "x" * MAX_LOGGED_LENGTH
    assert safe_for_log(at_the_bound) == at_the_bound


def test_ordinary_text_is_not_refused() -> None:
    """The rule is deliberately narrow.

    The control plane accepts any string of 1 to 255 characters as an endpoint
    key, so a stricter rule here would make an endpoint that registers cleanly
    impossible to report.
    """
    for value in (
        "finretail.orders",
        "délivéry.track",
        "配送.追跡",
        "a b c",
        "emoji 📦",
    ):
        assert not has_unsafe_key_characters(value)
        assert safe_for_log(value) == value
