"""The process: a configuration it can't serve exits 2, on one line."""

import os
import subprocess
import sys

import pytest


def _run_gateway(**settings: str) -> subprocess.CompletedProcess:
    """Run `python -m gateway.standalone` with no `RAIL_` variable but
    `settings`."""
    kept = {k: v for k, v in os.environ.items() if not k.startswith("RAIL_")}
    return subprocess.run(
        [sys.executable, "-m", "gateway.standalone"],
        env={**kept, **settings},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
        check=False,
    )


@pytest.mark.parametrize(
    ("settings", "named"),
    [
        (
            {"RAIL_GATEWAY_ROUTES_FILE": "/nonexistent/routes.yaml"},
            "cannot read /nonexistent/routes.yaml",
        ),
        (
            {
                "RAIL_GATEWAY_ROUTES_FILE": "/nonexistent/routes.yaml",
                "RAIL_GATEWAY_LOG_LEVEL": "LOUD",
            },
            "RAIL_GATEWAY_LOG_LEVEL must be one of",
        ),
        ({"RAIL_PLUGIN_ENABLED": "maybe"}, "RAIL_PLUGIN_ENABLED must be one of"),
    ],
    ids=["routes file", "log level", "plugin flag"],
)
def test_a_configuration_error_exits_2_without_a_traceback(settings, named):
    gateway = _run_gateway(**settings)

    assert gateway.returncode == 2, gateway.stdout
    assert named in gateway.stdout
    assert "Traceback" not in gateway.stdout
