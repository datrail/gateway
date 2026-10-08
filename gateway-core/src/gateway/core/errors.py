"""The error every interface's `main()` turns into exit 2."""


class ConfigError(Exception):
    """The configuration cannot be served. Raised rather than exited, so a
    caller importing the module isn't taken down past its own handlers;
    `main()` logs it on one line and exits 2."""
