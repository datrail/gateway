"""The component logger's level and handler."""

import logging

import pytest

from gateway.core.errors import ConfigError
from gateway.core.logs import configure_logging

# Where `configure_logging` installs the handler and level.
COMPONENT = logging.getLogger("gateway")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("", logging.INFO), ("   ", logging.INFO), ("debug", logging.DEBUG)],
)
def test_a_blank_or_valid_level_is_applied(monkeypatch, raw, expected):
    monkeypatch.setenv("RAIL_GATEWAY_LOG_LEVEL", raw)
    configure_logging()
    assert COMPONENT.level == expected


def test_configuring_twice_does_not_double_every_line(monkeypatch):
    """`main()` calls this once, but a test calling it again would otherwise
    leave the component logger printing everything twice for the rest of the
    run."""
    monkeypatch.setenv("RAIL_GATEWAY_LOG_LEVEL", "INFO")
    configure_logging()
    before = len(COMPONENT.handlers)
    configure_logging()
    assert len(COMPONENT.handlers) == before


@pytest.mark.parametrize("raw", ["verbose", "20", "TRACE"])
def test_an_unknown_level_is_refused_by_name(monkeypatch, raw):
    """`logging.getLevelName` answers "Level 20" for an unknown name rather than
    failing, so a typo would otherwise set a level nobody chose."""
    monkeypatch.setenv("RAIL_GATEWAY_LOG_LEVEL", raw)
    with pytest.raises(ConfigError, match="RAIL_GATEWAY_LOG_LEVEL must be one of"):
        configure_logging()
