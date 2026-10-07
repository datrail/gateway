"""Fixtures for the gateway-apigee-grpc suite."""

import os

import pytest


@pytest.fixture(autouse=True)
def clear_rail_environment(monkeypatch):
    """A `RAIL_` variable left in the shell would change what a test reads."""
    for name in list(os.environ):
        if name.startswith("RAIL_"):
            monkeypatch.delenv(name)
