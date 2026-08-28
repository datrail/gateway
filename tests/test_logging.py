"""The startup line, and what it must not carry."""

from __future__ import annotations

import logging

import pytest

from gateway.server import _configure_logging, _safe_to_log, build_gateway, log


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://gateway:8080/mcp", "http://gateway:8080/mcp"),
        ("https://user:s3cret@internal:9443/mcp", "https://internal:9443/mcp"),
        ("https://user@internal/mcp", "https://internal/mcp"),
        # A hosted MCP endpoint commonly carries its credential here, which
        # clearing the authority alone left untouched.
        ("https://host/mcp?api_key=SECRET", "https://host/mcp (query omitted)"),
        ("https://host/mcp#SECRET", "https://host/mcp (query omitted)"),
        # Reassembling from `hostname` dropped the brackets an IPv6 literal
        # needs, and reading `port` raised on one that is not a number.
        ("http://user:pw@[::1]:9443/mcp", "http://[::1]:9443/mcp"),
        ("http://user:pw@host:notaport/mcp", "http://host:notaport/mcp"),
    ],
)
def test_nothing_that_can_carry_a_secret_reaches_the_log(url, expected):
    assert _safe_to_log(url) == expected


def test_the_startup_line_itself_is_safe(caplog):
    """The helper being correct is not the property that matters — the call
    site using it is. Asserting only on `_safe_to_log` leaves a mutation that
    logs the raw URL passing the whole suite."""
    secret_url = "https://svcuser:s3cret@internal:9443/mcp?api_key=TOKEN"
    with caplog.at_level(logging.INFO, logger="gateway"):
        build_gateway(secret_url)

    written = "\n".join(caplog.messages)
    assert "forwarding to" in written
    assert "s3cret" not in written
    assert "TOKEN" not in written


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("", logging.INFO), ("   ", logging.INFO), ("debug", logging.DEBUG)],
)
def test_a_blank_or_valid_level_is_applied(monkeypatch, raw, expected):
    monkeypatch.setenv("RAIL_GATEWAY_LOG_LEVEL", raw)
    _configure_logging()
    assert log.level == expected


def test_configuring_twice_does_not_double_every_line(monkeypatch):
    """`main()` calls this once, but a test calling it again would otherwise
    leave the module logger printing everything twice for the rest of the run."""
    monkeypatch.setenv("RAIL_GATEWAY_LOG_LEVEL", "INFO")
    _configure_logging()
    before = len(log.handlers)
    _configure_logging()
    assert len(log.handlers) == before


@pytest.mark.parametrize("raw", ["verbose", "20", "TRACE"])
def test_an_unknown_level_is_refused_by_name(monkeypatch, raw):
    """`logging.getLevelName` answers "Level 20" for an unknown name rather than
    failing, so a typo would otherwise set a level nobody chose."""
    monkeypatch.setenv("RAIL_GATEWAY_LOG_LEVEL", raw)
    with pytest.raises(RuntimeError, match="RAIL_GATEWAY_LOG_LEVEL must be one of"):
        _configure_logging()
