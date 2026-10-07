"""The callout's own settings. Core's are tested in gateway-core."""

import pytest

from gateway.apigee_grpc.settings import get_max_message_bytes

_NAME = "RAIL_GATEWAY_GRPC_MAX_MESSAGE_MB"


def test_the_message_limit_defaults_to_16_mb():
    assert get_max_message_bytes() == 16 * 1048576


@pytest.mark.parametrize("raw", ["", "   "])
def test_a_blank_message_limit_means_the_default(monkeypatch, raw):
    monkeypatch.setenv(_NAME, raw)
    assert get_max_message_bytes() == 16 * 1048576


@pytest.mark.parametrize("raw", ["1", "100", " 32 "])
def test_a_limit_in_range_is_read_in_mb(monkeypatch, raw):
    monkeypatch.setenv(_NAME, raw)
    assert get_max_message_bytes() == int(raw) * 1048576


@pytest.mark.parametrize("raw", ["16MB", "1e1", "4.5", "lots"])
def test_a_message_limit_that_is_not_an_integer_is_refused(monkeypatch, raw):
    monkeypatch.setenv(_NAME, raw)
    with pytest.raises(RuntimeError, match=f"{_NAME} must be an integer, got: "):
        get_max_message_bytes()


@pytest.mark.parametrize("raw", ["0", "101", "-1", "16777216"])
def test_a_message_limit_outside_the_range_is_refused(monkeypatch, raw):
    monkeypatch.setenv(_NAME, raw)
    with pytest.raises(RuntimeError, match=f"{_NAME} must be between 1 and 100, got: "):
        get_max_message_bytes()
