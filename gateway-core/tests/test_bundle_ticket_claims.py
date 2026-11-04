"""The issuer and audience a bundle names, which signed tickets are compared
with (`ticket_issuer` and `ticket_audience`, `schema_version` `2.1`).

What a gateway then reads a signed ticket as, against them, is the shared
enforcement table's: a ticket for the tenant the bundle names is judged, one for
another tenant and one under a bundle not naming both are `wrong_audience`.
"""

import logging
from typing import Any

import pytest

from gateway.core.bundle.validate import validate_bundle

ISSUER = "https://rail-center.example/tenants/00000000-0000-4000-8000-0000000000aa"
AUDIENCE = "00000000-0000-4000-8000-0000000000aa"


def _bundle(schema_version: str = "2.1", **root: Any):
    return validate_bundle(
        {
            "schema_version": schema_version,
            "content_hash": "v",
            "policies": [],
            "bindings": [],
            "enforcement": {"mode": "enforce"},
            "binding_fallback": "pass",
            "ticket_fallback": "block",
            **root,
        }
    )


def test_a_bundle_naming_both_holds_them_exactly():
    held = _bundle(ticket_issuer=ISSUER, ticket_audience=AUDIENCE)

    assert (held.ticket_issuer, held.ticket_audience) == (ISSUER, AUDIENCE)


def test_a_bundle_from_before_2_1_names_neither():
    held = _bundle(schema_version="2.0")

    assert (held.ticket_issuer, held.ticket_audience) == (None, None)


@pytest.mark.parametrize("value", [None, "", "   "])
def test_null_or_blank_is_unset(value, caplog):
    """`null` is a Rail Center that signs no tickets; blank names nothing a
    ticket could match, and held as a string it would match `iss: ""`."""
    with caplog.at_level(logging.WARNING, logger="gateway.core.bundle.validate"):
        held = _bundle(ticket_issuer=value, ticket_audience=value)

    assert (held.ticket_issuer, held.ticket_audience) == (None, None)
    assert caplog.text == ""


@pytest.mark.parametrize("value", [42, ["a"], {"a": 1}, True])
def test_a_value_that_is_not_a_string_is_warned_and_unset(value, caplog):
    """Not refused: refusing would keep the bundle held before, freezing every
    policy change while the responder sent it, for a field that decides only
    whether a signed ticket is accepted — and holding it as unset fails closed."""
    with caplog.at_level(logging.WARNING, logger="gateway.core.bundle.validate"):
        held = _bundle(ticket_issuer=value, ticket_audience=AUDIENCE)

    assert held.ticket_issuer is None
    assert held.ticket_audience == AUDIENCE
    assert "ticket_issuer is a" in caplog.text
    # The bundle is still the one applied.
    assert held.ticket_fallback == "block"
