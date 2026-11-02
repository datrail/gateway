"""What a deployment sets to have signed tickets verified, and what it refuses.

Three variables: the issuer and audience a signed ticket must name, and
whether an unsigned ticket is still read. They are refused at startup in the
same words whichever interface reads them, and they count as Rail Center
configuration, so a gateway given them with the plugin off is told rather than
silently left verifying nothing.
"""

import httpx
import pytest
from test_keyset import ok, responder

from gateway.core.errors import ConfigError
from gateway.core.keyset import KeySetHolder
from gateway.core.lifecycle import is_ready
from gateway.core.mode import plugin_enabled
from gateway.core.settings import (
    REQUIRE_SIGNED_TICKETS,
    TICKET_AUDIENCE,
    TICKET_ISSUER,
    build_keyset,
    require_signed_tickets,
)

ISSUER = "https://rail-center.example/tenants/00000000-0000-4000-8000-0000000000aa"
AUDIENCE = "00000000-0000-4000-8000-0000000000aa"
HTTPS = "https://rail-center.example"


@pytest.fixture(autouse=True)
def _unset(monkeypatch):
    for name in (
        TICKET_ISSUER,
        TICKET_AUDIENCE,
        REQUIRE_SIGNED_TICKETS,
        "RAIL_PLUGIN_ENABLED",
        "RAIL_CENTER_URL",
        "RAIL_AUTH_MODE",
        "RAIL_AUTH_TOKEN",
        "RAIL_TICKET_MODE",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("", False), ("  ", False), ("false", False), ("true", True), (" TRUE ", True)],
)
def test_requiring_signatures_is_true_or_false_and_off_by_default(
    monkeypatch, raw, expected
):
    monkeypatch.setenv(REQUIRE_SIGNED_TICKETS, raw)

    assert require_signed_tickets() is expected


@pytest.mark.parametrize("raw", ["yes", "1", "on", "ture"])
def test_any_other_spelling_of_requiring_signatures_is_refused(monkeypatch, raw):
    """A typo read as `false` would accept unsigned tickets on a gateway whose
    operator meant to refuse them, which is the direction nobody notices."""
    monkeypatch.setenv(REQUIRE_SIGNED_TICKETS, raw)

    with pytest.raises(ConfigError, match=REQUIRE_SIGNED_TICKETS):
        require_signed_tickets()


def test_the_issuer_and_audience_reach_the_verifier_exactly(monkeypatch):
    monkeypatch.setenv(TICKET_ISSUER, f"  {ISSUER} ")
    monkeypatch.setenv(TICKET_AUDIENCE, AUDIENCE)

    verifier = build_keyset(HTTPS, {}).verifier()

    assert (verifier.issuer, verifier.audience) == (ISSUER, AUDIENCE)


@pytest.mark.parametrize("raw", ["", "   "])
def test_a_blank_issuer_or_audience_is_unset_and_not_the_empty_string(monkeypatch, raw):
    """The reader compares against whatever it is given. An empty issuer would
    match a ticket carrying `iss: ""`, where an unset one accepts nothing."""
    monkeypatch.setenv(TICKET_ISSUER, raw)
    monkeypatch.setenv(TICKET_AUDIENCE, raw)

    verifier = build_keyset(HTTPS, {}).verifier()

    assert (verifier.issuer, verifier.audience) == (None, None)


def test_requiring_signatures_over_plain_http_is_refused(monkeypatch):
    """No key set is ever fetched over anything but HTTPS, so that gateway
    would start cleanly and refuse every call."""
    monkeypatch.setenv(REQUIRE_SIGNED_TICKETS, "true")

    with pytest.raises(ConfigError, match="https"):
        build_keyset("http://rail-center.example", {})


def test_not_requiring_signatures_over_plain_http_starts(monkeypatch):
    """Unsigned tickets read as they always have, which is every e2e stack."""
    keys = build_keyset("http://rail-center.example", {})

    assert keys.verifier().requires_signatures is False


@pytest.mark.parametrize(
    ("name", "value"),
    [
        (TICKET_ISSUER, ISSUER),
        (TICKET_AUDIENCE, AUDIENCE),
        (REQUIRE_SIGNED_TICKETS, "true"),
    ],
)
def test_signed_ticket_settings_beside_a_plugin_that_is_off_are_refused(
    monkeypatch, name, value
):
    """A gateway told which tenant's signed tickets to accept, with no control
    plane to fetch the keys from, has been misconfigured, not left alone."""
    monkeypatch.setenv(name, value)

    with pytest.raises(ConfigError, match=name):
        plugin_enabled()


def test_requiring_signatures_set_to_false_asserts_nothing(monkeypatch):
    """`false` is the default spelled out, as `RAIL_AUTH_MODE=none` is."""
    monkeypatch.setenv(REQUIRE_SIGNED_TICKETS, " False ")

    assert plugin_enabled() is False


class _Held:
    """A bundle holder that holds one, for readiness alone."""

    def current(self):
        return object()


@pytest.mark.asyncio
async def test_a_gateway_requiring_signatures_is_ready_only_with_a_key_set():
    """Without one it refuses every call, so reporting itself ready would send
    traffic to a gateway that can only refuse it."""
    keys = KeySetHolder(
        HTTPS,
        {},
        issuer=ISSUER,
        audience=AUDIENCE,
        requires_signatures=True,
        transport=responder(ok()),
    )

    assert is_ready(_Held(), keys) is False
    await keys.refresh()
    assert is_ready(_Held(), keys) is True


def test_a_gateway_not_requiring_signatures_is_ready_on_the_bundle_alone():
    keys = KeySetHolder(
        HTTPS,
        {},
        issuer=ISSUER,
        audience=AUDIENCE,
        transport=httpx.MockTransport(lambda _request: httpx.Response(500)),
    )

    assert is_ready(_Held(), keys) is True
