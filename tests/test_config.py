"""Configuration errors belong at startup, not in the first request's log line."""

from __future__ import annotations

import base64

import httpx
import pytest

from gateway.auth import AuthConfigurationError
from gateway.mode import (
    ENFORCEMENTS,
    ENROLMENTS,
    TicketModeError,
    describe_enforcement,
    describe_enrolment,
    enrolment,
)
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


# --- RAIL_TICKET_MODE: enrolment, not posture ------------------------------
#
# RC-312 re-valued this variable. It answers *is there a control plane here* and
# nothing else; what to do with a call arrives in the bundle. `enrolment()` is
# the one enumerated reader nothing else in this suite reaches — every other
# test injects `enrolled=` into `build_app`, which skips it — so its default,
# its refusal and its case folding are pinned here or nowhere.


def test_an_unset_ticket_mode_is_plugin(monkeypatch):
    """The default asks the control plane rather than deciding without one.

    It is no longer `enforce`, because a posture is not what this variable says
    any more. A deployment that forgets the line still polls, and what it then
    does is whatever its operator set in Rail Center.
    """
    monkeypatch.delenv("RAIL_TICKET_MODE", raising=False)
    assert enrolment() == "plugin"


@pytest.mark.parametrize("raw", ["", "   ", "\t\n"])
def test_a_blank_ticket_mode_is_read_as_unset(monkeypatch, raw):
    monkeypatch.setenv("RAIL_TICKET_MODE", raw)
    assert enrolment() == "plugin"


@pytest.mark.parametrize(
    "raw", ["none", "plugin", " plugin ", "NONE", "None", "Plugin"]
)
def test_the_ticket_mode_is_read_case_insensitively(monkeypatch, raw):
    """One variable, read by two components, so both must resolve the same set.

    The proxy in front reads `RAIL_TICKET_MODE` through `.strip().lower()`. A
    gateway matching exactly would refuse to start on the `NONE` its proxy
    resolved happily — the zone configured correctly in front, and the component
    behind it refusing to boot.
    """
    monkeypatch.setenv("RAIL_TICKET_MODE", raw)
    assert enrolment() == raw.strip().lower()


@pytest.mark.parametrize("raw", ["observe", "enforce", "Enforce", "OBSERVE"])
def test_a_retired_posture_value_refuses_to_start_and_says_where_it_went(
    monkeypatch, raw
):
    """The deliberate break, and the reason it is a break rather than a
    translation.

    Reading `enforce` as `plugin` would let a deployment go on declaring a
    posture in a variable nothing reads, with the bundle quietly overruling it
    and nobody told. A component that will not boot is the cheaper failure,
    because it is the one an operator sees — and the message has to send them
    somewhere, or they will set it back.
    """
    monkeypatch.setenv("RAIL_TICKET_MODE", raw)
    with pytest.raises(TicketModeError, match="RAIL_TICKET_MODE must be one of"):
        enrolment()
    with pytest.raises(TicketModeError, match="arrives in the policy bundle"):
        enrolment()


@pytest.mark.parametrize("raw", ["plugged", "off", "block", "no ne", "none;plugin"])
def test_an_unrecognised_ticket_mode_refuses_to_start(monkeypatch, raw):
    """Refused rather than defaulted, and without the posture hint: a value that
    was never one of the three is a typo, not a migration."""
    monkeypatch.setenv("RAIL_TICKET_MODE", raw)
    with pytest.raises(
        TicketModeError, match="RAIL_TICKET_MODE must be one of"
    ) as raised:
        enrolment()
    assert "arrives in the policy bundle" not in str(raised.value)


def test_a_refused_ticket_mode_names_what_the_operator_wrote(monkeypatch):
    """The folded form is what is matched; the raw one is what is reported, so
    a value refused for some reason other than its case reads back to whoever
    set it."""
    monkeypatch.setenv("RAIL_TICKET_MODE", "Plugged")
    with pytest.raises(TicketModeError, match="Plugged"):
        enrolment()


# --- the startup line, and the posture line --------------------------------
#
# Two lines now, written at two moments. `build_gateway` writes the enrolment
# line at INFO on every start; the posture line is what a poll has to say when
# the bundle moves. `test_readiness.py`'s control-plane-down case filters the
# banner out by `RAIL_TICKET_MODE=` prefix, so what these say is pinned here.


@pytest.mark.parametrize("enrolled", ENROLMENTS)
def test_each_startup_line_names_the_enrolment_it_describes(enrolled):
    """A line naming the wrong state is worse than no line: it is the log an
    operator checks *instead of* sending a request."""
    assert describe_enrolment(enrolled).startswith(f"RAIL_TICKET_MODE={enrolled} — ")


def test_the_two_startup_lines_do_not_repeat_each_other():
    assert describe_enrolment("none") != describe_enrolment("plugin")


def test_the_plugin_line_promises_nothing_about_traffic():
    """The line an unconfigured deployment now writes, and the claim it must not
    make. What this gateway does to a request is the bundle's to say and is not
    known at start-up, so a start-up line naming a posture would be a guess an
    operator reads as a fact."""
    line = describe_enrolment("plugin")

    assert "polls Rail Center" in line
    assert "judges nothing" in line and "unready" in line
    assert "403" not in line and "blocked" not in line


def test_the_none_line_says_there_is_no_control_plane():
    """`none` means no control plane after RC-312, not "do not enforce". The
    second half matters as much: an operator debugging a control plane this
    gateway is not talking to needs to be told it never will."""
    line = describe_enrolment("none")

    assert "no control plane" in line
    assert "forwards every request" in line
    assert "fetches no policy bundle" in line


@pytest.mark.parametrize("enforcement", ENFORCEMENTS)
def test_each_posture_line_names_the_enforcement_it_describes(enforcement):
    assert describe_enforcement(enforcement, "block").startswith(
        f"enforcement={enforcement} — "
    )


def test_the_enforce_line_says_the_traffic_it_refuses():
    """Both refusals named, and the claim this line used to carry — that
    enforcement is not implemented and the mode behaves as observe — may not
    come back."""
    line = describe_enforcement("enforce", "block")

    assert "403" in line and "503" in line
    assert "reported to Rail Center" in line
    assert "nothing is blocked" not in line
    assert "not implemented" not in line


def test_the_observe_line_says_nothing_is_blocked():
    line = describe_enforcement("observe", "block")

    assert "nothing is blocked" in line
    assert "403" not in line and "503" not in line
    assert "refus" not in line


def test_the_none_posture_line_says_it_keeps_polling():
    """The half that is easy to leave out and is the whole of RC-312 on this
    side: a gateway told `none` is still listening, so an operator can move it
    back without a redeploy."""
    line = describe_enforcement("none", "block")

    assert "forwarded" in line
    assert "keeps polling" in line
    assert "403" not in line and "503" not in line


@pytest.mark.parametrize("enforcement", ["none", "observe"])
def test_the_fallback_is_named_only_where_it_decides_something(enforcement):
    """It is consulted at `enforce` and nowhere else, so a line mentioning it
    anywhere else invites an operator to think it applies there."""
    assert "fallback" not in describe_enforcement(enforcement, "pass")


def test_the_enforce_line_says_what_each_fallback_does_to_an_unbound_endpoint():
    """The pair whose meaning RC-312 corrected, so the two lines must differ in
    the direction the correction went: `pass` is not "unjudged"."""
    blocked = describe_enforcement("enforce", "block")
    passed = describe_enforcement("enforce", "pass")

    assert "fallback=block" in blocked and "without consulting the chain" in blocked
    assert "fallback=pass" in passed and "judged by the whole chain" in passed
    assert "unjudged" not in passed
