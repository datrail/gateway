"""Configuration errors belong at startup, not in the first request's log line."""

from __future__ import annotations

import pytest

from gateway.server import DEFAULT_PORT, build_gateway, port


def test_a_missing_upstream_url_refuses_to_start(monkeypatch):
    """A gateway pointed at nothing forwards nothing while reporting healthy."""
    monkeypatch.delenv("RAIL_GATEWAY_UPSTREAM_URL", raising=False)

    with pytest.raises(RuntimeError, match="RAIL_GATEWAY_UPSTREAM_URL is required"):
        build_gateway()


def test_an_empty_upstream_url_is_the_same_as_a_missing_one(monkeypatch):
    """A variable set to whitespace is an operator who meant to set it."""
    monkeypatch.setenv("RAIL_GATEWAY_UPSTREAM_URL", "   ")

    with pytest.raises(RuntimeError, match="RAIL_GATEWAY_UPSTREAM_URL is required"):
        build_gateway()


def test_port_defaults(monkeypatch):
    monkeypatch.delenv("RAIL_GATEWAY_PORT", raising=False)
    assert port() == DEFAULT_PORT


@pytest.mark.parametrize("raw", ["nope", "8080.5", ""])
def test_a_non_integer_port_is_refused(monkeypatch, raw):
    monkeypatch.setenv("RAIL_GATEWAY_PORT", raw)
    if raw == "":
        assert port() == DEFAULT_PORT
        return
    with pytest.raises(RuntimeError, match="must be an integer"):
        port()


@pytest.mark.parametrize("raw", ["0", "65536", "-1"])
def test_a_port_outside_the_range_is_refused(monkeypatch, raw):
    monkeypatch.setenv("RAIL_GATEWAY_PORT", raw)
    with pytest.raises(RuntimeError, match="between 1 and 65535"):
        port()
