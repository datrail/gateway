"""What the callout reads from the environment besides core's settings."""

import os

from gateway.core.errors import ConfigError

_MB = 1024 * 1024
# Apigee X takes request bodies up to 10 MB, and gRPC's own default is 4 MB.
_DEFAULT_MAX_MESSAGE_MB = 16
_MIN_MAX_MESSAGE_MB = 1
_MAX_MAX_MESSAGE_MB = 100


def _get_env(name: str) -> str:
    """The variable's value, stripped; empty when unset."""
    return (os.environ.get(name) or "").strip()


def get_max_message_bytes() -> int:
    """The largest gRPC message the callout receives or sends, in bytes.

    Set in MB. Blank or unset is the default, as for `RAIL_GATEWAY_PORT`.
    """
    name = "RAIL_GATEWAY_GRPC_MAX_MESSAGE_MB"
    raw = _get_env(name)
    if not raw:
        return _DEFAULT_MAX_MESSAGE_MB * _MB
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer, got: {raw}") from None
    if not _MIN_MAX_MESSAGE_MB <= value <= _MAX_MAX_MESSAGE_MB:
        raise ConfigError(
            f"{name} must be between {_MIN_MAX_MESSAGE_MB} and "
            f"{_MAX_MAX_MESSAGE_MB}, got: {value}"
        )
    return value * _MB
