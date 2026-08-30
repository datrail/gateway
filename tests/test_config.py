"""Configuration errors belong at startup, not in the first request's log line."""

from __future__ import annotations

import base64

import httpx
import pytest

from gateway.auth import AuthConfigurationError
from gateway.mode import TICKET_MODES, TicketModeError, describe, ticket_mode
from gateway.server import (
    DEFAULT_PORT,
    _holder_from_environment,
    build_gateway,
    port,
)


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


def test_a_missing_rail_center_url_refuses_to_start(monkeypatch):
    """The same rule as the upstream, and the failure it prevents is worse: a
    gateway that cannot resolve where its control plane is fetches no bundle
    ever, and reports that in the log as a control plane which is down."""
    monkeypatch.setenv("RAIL_GATEWAY_UPSTREAM_URL", "http://upstream.invalid/mcp")
    monkeypatch.delenv("RAIL_CENTER_URL", raising=False)

    with pytest.raises(RuntimeError, match="RAIL_CENTER_URL is required"):
        build_gateway()


@pytest.mark.parametrize("url", ["http://", "http://user:pw@", "https://"])
def test_a_rail_center_url_with_no_host_refuses_to_start(monkeypatch, url):
    monkeypatch.setenv("RAIL_GATEWAY_UPSTREAM_URL", "http://upstream.invalid/mcp")
    monkeypatch.setenv("RAIL_CENTER_URL", url)

    with pytest.raises(RuntimeError, match="RAIL_CENTER_URL names no host"):
        build_gateway()


def test_a_rail_center_url_with_no_scheme_keeps_its_credential_out_of_the_error(
    monkeypatch,
):
    """The other half of the same refusal, carrying a secret. Forgetting the
    scheme is the whole of what it takes: `svcuser:pw@host/` parses as a scheme
    with the rest as path, so there is no host and no netloc either — and a
    redaction that rebuilds from the netloc has nothing to strip and hands back
    the password whole, into the stderr of a failed start."""
    monkeypatch.setenv("RAIL_GATEWAY_UPSTREAM_URL", "http://upstream.invalid/mcp")
    monkeypatch.setenv(
        "RAIL_CENTER_URL", "svcuser:s3cret-rc-password@rail-center.test/"
    )

    with pytest.raises(RuntimeError) as raised:
        build_gateway()

    message = str(raised.value)
    assert "RAIL_CENTER_URL names no host" in message
    assert "s3cret-rc-password" not in message
    assert "svcuser" not in message


def test_an_unparseable_upstream_url_names_the_upstream():
    """The sibling of "names no host", reached through the branch above it: an
    unclosed IPv6 bracket raises out of `urlsplit` before any host check runs.
    `_checked_url` is shared by both address variables and interpolates the one
    it was given, so what an operator is told is which of the two they mistyped
    — and that is the whole reason the message is not a constant."""
    with pytest.raises(
        RuntimeError, match="RAIL_GATEWAY_UPSTREAM_URL is not a URL that can be parsed"
    ):
        build_gateway("http://[::1")


def test_an_unparseable_rail_center_url_names_the_control_plane(monkeypatch):
    """The other half of the same helper. Named separately because a message
    hardcoded to either variable passes the case for that one."""
    monkeypatch.setenv("RAIL_GATEWAY_UPSTREAM_URL", "http://upstream.invalid/mcp")
    monkeypatch.setenv("RAIL_CENTER_URL", "http://[::1")

    with pytest.raises(
        RuntimeError, match="RAIL_CENTER_URL is not a URL that can be parsed"
    ):
        build_gateway()


def test_an_unparseable_url_carrying_no_credential_keeps_its_diagnostic(monkeypatch):
    """The common case of that branch, and the one the redactor can spoil. With
    no userinfo to remove, `str.replace("", "***")` would put the marker between
    every character of the message — `***I***n***v***a***l***i***d***…` — and
    the operator loses the half of it that says what they mistyped."""
    monkeypatch.setenv("RAIL_GATEWAY_UPSTREAM_URL", "http://upstream.invalid/mcp")
    monkeypatch.setenv("RAIL_CENTER_URL", "http://[::1")

    with pytest.raises(RuntimeError) as raised:
        build_gateway()

    message = str(raised.value)
    assert message.endswith(": Invalid IPv6 URL")
    assert "***" not in message


@pytest.mark.parametrize(
    "prefix",
    [
        "http://",
        # A scheme-relative value reaches `_checknetloc` exactly as `http://`
        # does, so the raising path is identical and only the redaction differs
        # — and a redaction reading the authority off `://` finds none here.
        "//",
    ],
)
def test_an_unparseable_rail_center_url_keeps_its_credential_out_of_the_error(
    monkeypatch, prefix
):
    """The same branch, carrying a secret. `urlsplit` quotes the whole netloc
    in the `ValueError` it raises for a host that normalises into a delimiter
    ("\u2100" is NFKC "a/c"), so the raw exception text carries the userinfo
    with it. That message is what a failed start writes to stderr, and stderr
    is what the container's log collector and every CI job running the image
    keep — so the control plane's password cannot be in it."""
    monkeypatch.setenv("RAIL_GATEWAY_UPSTREAM_URL", "http://upstream.invalid/mcp")
    monkeypatch.setenv(
        "RAIL_CENTER_URL",
        f"{prefix}svcuser:s3cret-rc-password@rail\u2100center.test/",
    )

    with pytest.raises(RuntimeError) as raised:
        build_gateway()

    message = str(raised.value)
    assert "RAIL_CENTER_URL is not a URL that can be parsed" in message
    assert "s3cret-rc-password" not in message
    assert "svcuser" not in message


@pytest.mark.parametrize("tail", ["?x@y", "#x@y"])
def test_a_query_or_fragment_does_not_let_the_credential_through(monkeypatch, tail):
    """The same secret, in a URL that carries a query or a fragment. Where the
    authority is read off the raw string, whatever ends it has to be every
    delimiter that can — a scan that stops only at `/` reads `...test?x` as the
    credential, finds no such text in the message, and hands the password back
    whole. Asserted on the outcome and not on the scan: what must hold is that
    nothing quotable reaches stderr, whichever way the authority is found."""
    monkeypatch.setenv("RAIL_GATEWAY_UPSTREAM_URL", "http://upstream.invalid/mcp")
    monkeypatch.setenv(
        "RAIL_CENTER_URL",
        f"http://svcuser:s3cret-rc-password@rail\u2100center.test{tail}",
    )

    with pytest.raises(RuntimeError) as raised:
        build_gateway()

    message = str(raised.value)
    assert "RAIL_CENTER_URL is not a URL that can be parsed" in message
    assert "s3cret-rc-password" not in message
    assert "svcuser" not in message


def test_the_upstream_is_checked_before_the_control_plane(monkeypatch):
    """An operator who has set neither should be told about the one they would
    fix first, not handed whichever check happens to run first."""
    monkeypatch.delenv("RAIL_GATEWAY_UPSTREAM_URL", raising=False)
    monkeypatch.delenv("RAIL_CENTER_URL", raising=False)

    with pytest.raises(RuntimeError, match="RAIL_GATEWAY_UPSTREAM_URL is required"):
        build_gateway()


def test_a_credential_that_cannot_be_sent_is_refused_at_startup(monkeypatch):
    """Resolved while `build_gateway` runs, not at the first fetch. Deferred, a
    mistyped secret would surface as a bundle that never arrives, long after
    the deploy that caused it and with nothing naming the cause."""
    monkeypatch.setenv("RAIL_GATEWAY_UPSTREAM_URL", "http://upstream.invalid/mcp")
    monkeypatch.setenv("RAIL_CENTER_URL", "http://rail-center.invalid")
    monkeypatch.setenv("RAIL_AUTH_MODE", "bearer")
    monkeypatch.setenv("RAIL_AUTH_TOKEN", "line-one\nline-two")

    with pytest.raises(AuthConfigurationError, match="RAIL_AUTH_TOKEN holds U\\+000A"):
        build_gateway()


def test_an_unreadable_refresh_interval_is_refused_at_startup(monkeypatch):
    """Same reasoning, same place. `refresh_seconds` raises on a value that is
    not a number, and it has to be called somewhere a caller sees it.

    The auth variables are cleared because `_holder_from_environment` reaches
    `auth_headers()` first: either of them set in the shell running the suite
    raises before the interval is ever read, and this case then fails on
    correct code with a message about a credential. `.env.example` documents
    both, so a contributor's shell is exactly where they turn up.
    """
    monkeypatch.setenv("RAIL_GATEWAY_UPSTREAM_URL", "http://upstream.invalid/mcp")
    monkeypatch.setenv("RAIL_CENTER_URL", "http://rail-center.invalid")
    monkeypatch.delenv("RAIL_AUTH_MODE", raising=False)
    monkeypatch.delenv("RAIL_AUTH_TOKEN", raising=False)
    monkeypatch.setenv("RAIL_GATEWAY_BUNDLE_REFRESH_SECONDS", "often")

    with pytest.raises(RuntimeError, match="must be an integer"):
        build_gateway()


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
    monkeypatch.delenv("RAIL_AUTH_MODE", raising=False)
    monkeypatch.delenv("RAIL_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("RAIL_GATEWAY_BUNDLE_REFRESH_SECONDS", raising=False)

    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(503)

    holder = _holder_from_environment()
    holder._transport = httpx.MockTransport(record)
    await holder.refresh()

    expected = base64.b64encode(b"user:s3cret").decode()
    assert seen[0].headers["Authorization"] == f"Basic {expected}"
    assert "s3cret" not in str(seen[0].url)


def test_two_rail_center_credentials_are_refused_at_startup(monkeypatch):
    """Only one `Authorization` header goes out, so an operator who set both
    has one of them silently discarded — and which one is httpx's choice rather
    than theirs. The same rule `auth.py` states for a credential that cannot be
    produced: stop, rather than call with something else."""
    monkeypatch.setenv("RAIL_GATEWAY_UPSTREAM_URL", "http://upstream.invalid/mcp")
    monkeypatch.setenv("RAIL_CENTER_URL", "http://user:s3cret@rail-center.invalid")
    monkeypatch.setenv("RAIL_AUTH_MODE", "bearer")
    monkeypatch.setenv("RAIL_AUTH_TOKEN", "configured-token")

    with pytest.raises(RuntimeError, match="only one of them can be sent"):
        build_gateway()


# --- RAIL_TICKET_MODE ------------------------------------------------------
#
# `ticket_mode()` is the one enumerated variable nothing else in this suite
# reaches: every other test injects `mode=` into `build_app`, which skips the
# reader entirely. What that leaves unpinned is the whole of the function —
# its default, its refusal, and the case folding that makes one platform-wide
# value configure a zone.


def test_an_unset_ticket_mode_is_enforce(monkeypatch):
    """The default is the strict one, so a deployment that forgets a line does
    not silently stop protecting anything."""
    monkeypatch.delenv("RAIL_TICKET_MODE", raising=False)
    assert ticket_mode() == "enforce"


@pytest.mark.parametrize("raw", ["", "   ", "\t\n"])
def test_a_blank_ticket_mode_is_read_as_unset(monkeypatch, raw):
    monkeypatch.setenv("RAIL_TICKET_MODE", raw)
    assert ticket_mode() == "enforce"


@pytest.mark.parametrize(
    "raw",
    ["none", "observe", "enforce", " enforce ", "NONE", "None", "Enforce", "OBSERVE"],
)
def test_the_ticket_mode_is_read_case_insensitively(monkeypatch, raw):
    """One variable, read by two components, so both must resolve the same set.

    The proxy in front reads `RAIL_TICKET_MODE` through `.strip().lower()`. A
    gateway matching exactly would refuse to start on the `NONE` or `Enforce`
    its proxy resolved happily — the zone is configured correctly in front and
    the component behind it will not boot.
    """
    monkeypatch.setenv("RAIL_TICKET_MODE", raw)
    assert ticket_mode() == raw.strip().lower()


@pytest.mark.parametrize(
    "raw", ["enforcing", "off", "block", "en force", "none;observe"]
)
def test_an_unrecognised_ticket_mode_refuses_to_start(monkeypatch, raw):
    """Refused rather than defaulted. Falling back to `enforce` is a deployment
    enforcing where its operator wrote `none`; falling back to `none` is one
    enforcing nothing while its operator believes it is. Neither is a guess
    worth making on an operator's behalf."""
    monkeypatch.setenv("RAIL_TICKET_MODE", raw)
    with pytest.raises(TicketModeError, match="RAIL_TICKET_MODE must be one of"):
        ticket_mode()


def test_a_refused_ticket_mode_names_what_the_operator_wrote(monkeypatch):
    """The folded form is what is matched; the raw one is what is reported, so
    a value refused for some reason other than its case reads back to whoever
    set it."""
    monkeypatch.setenv("RAIL_TICKET_MODE", "Enforcing")
    with pytest.raises(TicketModeError, match="Enforcing"):
        ticket_mode()


# --- the startup line each mode writes -------------------------------------
#
# `build_gateway` writes `describe(resolved_mode)` at INFO on every start, and
# `mode.py` states what that line is for: an operator is told what this mode
# does to traffic rather than discovering it from a request that was refused.
# The one test that sees the banner — `test_readiness.py`'s control-plane-down
# case — filters it out by `RAIL_TICKET_MODE=` prefix before asserting, so what
# the line says has to be pinned here or nowhere.


@pytest.mark.parametrize("mode", TICKET_MODES)
def test_each_startup_line_names_the_mode_it_describes(mode):
    """A line naming the wrong mode is worse than no line: it is the log an
    operator checks *instead of* sending a request."""
    assert describe(mode).startswith(f"RAIL_TICKET_MODE={mode} — ")


def test_the_three_startup_lines_do_not_repeat_each_other():
    """Three modes, three answers about traffic. A line shared between two of
    them is one of the two lying, and nothing else in the log corrects it."""
    assert len({describe(mode) for mode in TICKET_MODES}) == len(TICKET_MODES)


def test_the_enforce_line_says_the_traffic_it_refuses():
    """`enforce` is the default, so this is the line every unconfigured
    deployment writes, on a build that answers 403 and 503. Both refusals are
    named, and the claim this line used to carry — that enforcement is not
    implemented and the mode behaves as observe — may not come back."""
    line = describe("enforce")

    assert "403" in line and "503" in line
    assert "reported to Rail Center" in line
    assert "nothing is blocked" not in line
    assert "not implemented" not in line


def test_the_observe_line_says_nothing_is_blocked():
    """The half of the pair that must stay true of `observe` alone: it
    evaluates and logs, and no request is refused for it."""
    line = describe("observe")

    assert "nothing is blocked" in line
    assert "403" not in line and "503" not in line
    assert "refus" not in line


def test_the_none_line_says_nothing_is_evaluated():
    """`none` is a pass-through, and the second half matters as much: a gateway
    that will never read a bundle does not poll for one, and an operator
    debugging a control plane it is not talking to needs to know that here."""
    line = describe("none")

    assert "forwards every request" in line
    assert "no policy bundle is fetched" in line
    assert "403" not in line and "503" not in line
