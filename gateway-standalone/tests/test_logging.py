"""The startup line, and what it must not carry."""

import logging

from gateway.core.bundle.client import logger as bundle_client_logger
from gateway.core.bundle.validate import logger as bundle_validation_logger
from gateway.core.denial import logger as denial_logger
from gateway.core.enforcement import log as enforcement_logger
from gateway.core.lifecycle import log as lifecycle_logger
from gateway.standalone.routes import Route
from gateway.standalone.routes import log as routes_logger
from gateway.standalone.server import build_gateway
from gateway.standalone.server import log as server_logger

# Where `configure_logging` installs the handler and level.
COMPONENT = logging.getLogger("gateway")


def test_the_startup_line_itself_is_safe(caplog):
    """The helper being correct is not the property that matters — the call
    site using it is. Asserting only on `_safe_to_log` leaves a mutation that
    logs the raw URL passing the whole suite."""
    from standalone_support import holder_serving, unreachable

    secret_url = "https://svcuser:s3cret@host.invalid:9443/mcp?api_key=TOKEN"
    with caplog.at_level(logging.INFO, logger="gateway"):
        build_gateway(
            Route(name="delivery", url=secret_url, prefix="/"),
            holder_serving(unreachable),
        )

    written = "\n".join(caplog.messages)
    assert "forwarding to" in written
    assert "s3cret" not in written
    assert "TOKEN" not in written


def test_core_logs_remain_children_of_the_configured_component_logger():
    """Every module logger is a child of ``gateway``, core's included.

    The process installs its handler and selected level on ``gateway``. A
    logger outside it would bypass that handler, dropping INFO events and
    leaving warnings to Python's unformatted last-resort handler.
    """
    for logger in (
        bundle_client_logger,
        bundle_validation_logger,
        denial_logger,
        enforcement_logger,
        lifecycle_logger,
        routes_logger,
        server_logger,
    ):
        ancestor = logger.parent
        while ancestor is not None and ancestor is not COMPONENT:
            ancestor = ancestor.parent
        assert ancestor is COMPONENT, logger.name
