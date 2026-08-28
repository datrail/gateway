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


@pytest.mark.parametrize("raw", ["nope", "8080.5"])
def test_a_non_integer_port_is_refused(monkeypatch, raw):
    monkeypatch.setenv("RAIL_GATEWAY_PORT", raw)
    with pytest.raises(RuntimeError, match="must be an integer"):
        port()


@pytest.mark.parametrize("raw", ["", "   "])
def test_an_empty_or_blank_port_means_the_default(monkeypatch, raw):
    """Read the same way `_required` reads a blank: as unset, not as a value.

    Without stripping first, whitespace reaches `int()` and the error names an
    empty string back at the operator who set spaces.
    """
    monkeypatch.setenv("RAIL_GATEWAY_PORT", raw)
    assert port() == DEFAULT_PORT


@pytest.mark.parametrize("raw", ["0", "65536", "-1"])
def test_a_port_outside_the_range_is_refused(monkeypatch, raw):
    monkeypatch.setenv("RAIL_GATEWAY_PORT", raw)
    with pytest.raises(RuntimeError, match="between 1 and 65535"):
        port()


@pytest.mark.parametrize("url", ["http://", "http://user:pw@", "https://"])
def test_an_upstream_url_with_no_host_refuses_to_start(url):
    """Both parse, and a gateway built on either starts and answers /health
    while able to forward nothing — the condition the required-variable check
    exists to prevent, reached by a different door."""
    with pytest.raises(RuntimeError, match="names no host"):
        build_gateway(url)
