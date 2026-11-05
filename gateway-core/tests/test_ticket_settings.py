"""What a deployment sets to have signed tickets verified: nothing.

The key set comes from the Rail Center and credential the bundle holder uses,
and a ticket's own form decides how it is read, so a gateway reads both forms
without a setting, and its readiness stays the bundle's.
"""

import pytest

from gateway.core.keyset import KeySetHolder
from gateway.core.lifecycle import is_ready
from gateway.core.settings import build_keyset

HTTPS = "https://rail-center.example"


def test_the_key_set_carries_no_issuer_audience_or_requirement():
    """The issuer and audience come from the held bundle, not from the key set
    or any setting; and it reads an unsigned ticket as before."""
    verifier = build_keyset(HTTPS, {}).verifier()

    assert (verifier.issuer, verifier.audience) == (None, None)
    assert verifier.requires_signatures is False


def test_a_plain_http_rail_center_still_starts():
    """No key set is fetched over it, and unsigned tickets read as they always
    have, which is every stack that reaches Rail Center over plain HTTP."""
    assert isinstance(build_keyset("http://rail-center.example", {}), KeySetHolder)


class _Held:
    """A bundle holder that holds one, for readiness alone."""

    def current(self):
        return object()


@pytest.mark.parametrize("held", [_Held(), None])
def test_readiness_is_the_bundles_alone(held):
    """A key set decides nothing a first request needs."""
    assert is_ready(held) is True
