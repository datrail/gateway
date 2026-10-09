"""The settings every interface reads, and the redaction of what they log."""

import base64

import httpx
import pytest

from gateway.core.errors import ConfigError
from gateway.core.settings import DEFAULT_PORT, _safe_to_log, build_holder, port


def test_port_defaults(monkeypatch):
    """8080, with the literal asserted beside the constant.

    `EXPOSE 8080` in the Dockerfile, `-p 8080:8080` in the README and the e2e
    health checks all name it, so the default is a contract with the image
    rather than an internal choice. `port() == DEFAULT_PORT` alone moves with the
    constant and pins nothing: it holds just as well at 9091, with every one of
    those four out of step.
    """
    monkeypatch.delenv("RAIL_GATEWAY_PORT", raising=False)
    assert port() == DEFAULT_PORT == 8080


@pytest.mark.parametrize("raw", ["nope", "8080.5"])
def test_a_non_integer_port_is_refused(monkeypatch, raw):
    monkeypatch.setenv("RAIL_GATEWAY_PORT", raw)
    with pytest.raises(ConfigError, match="must be an integer"):
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
    with pytest.raises(ConfigError, match="between 1 and 65535"):
        port()


@pytest.mark.asyncio
async def test_a_credential_in_the_rail_center_url_travels_in_the_header(monkeypatch):
    """httpx derives `BasicAuth` from a URL's userinfo and *overwrites* the
    `Authorization` header it was handed, so a credential left in
    `RAIL_CENTER_URL` decides what this gateway calls its control plane with.
    Moved into the header, as the upstream URL's already is, there is nothing
    left in the URL for httpx to derive from — and nothing in the request line,
    where a credential does not belong either.

    Asserted on the wire, because the displacement happens inside httpx.
    """
    monkeypatch.setenv("RAIL_CENTER_URL", "http://user:s3cret@rail-center.invalid")
    monkeypatch.setenv("RAIL_GATEWAY_SLUG", "edge")
    monkeypatch.delenv("RAIL_AUTH_MODE", raising=False)
    monkeypatch.delenv("RAIL_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("RAIL_GATEWAY_BUNDLE_REFRESH_SECONDS", raising=False)

    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(503)

    holder = build_holder()
    holder._transport = httpx.MockTransport(record)
    await holder.refresh()

    expected = base64.b64encode(b"user:s3cret").decode()
    assert seen[0].headers["Authorization"] == f"Basic {expected}"
    assert "s3cret" not in str(seen[0].url)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://gateway:8080/mcp", "http://gateway:8080/mcp"),
        ("https://user:s3cret@host.invalid:9443/mcp", "https://host.invalid:9443/mcp"),
        ("https://user@host.invalid/mcp", "https://host.invalid/mcp"),
        # A hosted MCP endpoint commonly carries its credential here, which
        # clearing the authority alone left untouched.
        ("https://host/mcp?api_key=SECRET", "https://host/mcp (query omitted)"),
        ("https://host/mcp#SECRET", "https://host/mcp (fragment omitted)"),
        # Reassembling from `hostname` dropped the brackets an IPv6 literal
        # needs, and reading `port` raised on one that is not a number.
        ("http://user:pw@[::1]:9443/mcp", "http://[::1]:9443/mcp"),
        ("http://user:pw@host:notaport/mcp", "http://host:notaport/mcp"),
        # A userinfo short enough to occur again in the host or the path.
        # Redacting every occurrence of it rather than the one in front of the
        # `@` overwrote both — `https://***.default.***.cluster.local:8080/mcp`
        # — and scheme, host and path are what the line is read for.
        (
            "https://svc@svc.default.svc.cluster.local:8080/mcp",
            "https://svc.default.svc.cluster.local:8080/mcp",
        ),
        (
            "http://api@internal.example.com/api/mcp",
            "http://internal.example.com/api/mcp",
        ),
    ],
)
def test_nothing_that_can_carry_a_secret_reaches_the_log(url, expected):
    assert _safe_to_log(url) == expected
