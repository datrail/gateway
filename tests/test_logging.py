"""The startup line, and what it must not carry."""

from __future__ import annotations

import pytest

from gateway.server import _configure_logging, _redacted


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://gateway:8080/mcp", "http://gateway:8080/mcp"),
        ("https://user:s3cret@internal:9443/mcp", "https://***@internal:9443/mcp"),
        ("https://user@internal/mcp", "https://***@internal/mcp"),
    ],
)
def test_a_credential_in_the_upstream_url_never_reaches_the_log(url, expected):
    """RAIL_GATEWAY_UPSTREAM_URL can legitimately carry `user:password@`, and
    the line naming it is written on every start."""
    assert _redacted(url) == expected


@pytest.mark.parametrize("raw", ["", "   ", "info", " INFO "])
def test_a_blank_or_valid_level_is_accepted(monkeypatch, raw):
    monkeypatch.setenv("RAIL_GATEWAY_LOG_LEVEL", raw)
    _configure_logging()


@pytest.mark.parametrize("raw", ["verbose", "20", "TRACE"])
def test_an_unknown_level_is_refused_by_name(monkeypatch, raw):
    """`logging.getLevelName` answers "Level 20" for an unknown name rather than
    failing, so a typo would otherwise set a level nobody chose."""
    monkeypatch.setenv("RAIL_GATEWAY_LOG_LEVEL", raw)
    with pytest.raises(RuntimeError, match="RAIL_GATEWAY_LOG_LEVEL must be one of"):
        _configure_logging()
