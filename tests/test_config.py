"""Configuration errors belong at startup, not in the first request's log line."""

from __future__ import annotations

import base64
import logging

import httpx
import pytest

from gateway.auth import AuthConfigurationError
from gateway.mode import (
    ENFORCEMENTS,
    PluginConfigError,
    describe_enforcement,
    describe_plugin,
    plugin_enabled,
)
from gateway.routes import Route, RoutesError
from gateway.server import (
    DEFAULT_PORT,
    _Enforcement,
    _holder_from_environment,
    build_app,
    build_gateway,
    gateway_slug,
    port,
)


@pytest.fixture(autouse=True)
def enrolled(monkeypatch):
    """Every test below reaches code that only runs with the plugin on.

    `RAIL_PLUGIN_ENABLED` defaults to false, so a gateway built without it
    never reads `RAIL_CENTER_URL` at all — which would make most of this module
    pass by not executing the check it names. Set here rather than in each
    test, because for all of them but the block that pins the flag itself it is
    a precondition rather than the subject; that block sets or clears it
    explicitly and overrides this.
    """
    monkeypatch.setenv("RAIL_PLUGIN_ENABLED", "true")
    monkeypatch.setenv("RAIL_GATEWAY_SLUG", "edge")


#: A well-formed upstream, for the tests whose subject is some other variable.
UPSTREAM = "http://upstream.invalid/mcp"


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
    while able to forward nothing — the condition this check exists to prevent,
    and it is per route now that a gateway fronts several."""
    with pytest.raises(RuntimeError, match="names no host"):
        build_gateway(Route(name="delivery", url=url, prefix="/"))


def test_a_refused_upstream_url_names_the_route_that_carries_it():
    """One gateway fronts several upstreams, so a message naming the variable
    would name nothing an operator could go and fix. The route's own label is
    what they wrote in the file."""
    with pytest.raises(RuntimeError, match="finretail"):
        build_gateway(Route(name="finretail", url="http://", prefix="/fr"))


def test_a_missing_rail_center_url_refuses_to_start(monkeypatch):
    """The same rule as the upstream, and the failure it prevents is worse: a
    gateway that cannot resolve where its control plane is fetches no bundle
    ever, and reports that in the log as a control plane which is down."""
    monkeypatch.delenv("RAIL_CENTER_URL", raising=False)

    with pytest.raises(RuntimeError, match="RAIL_CENTER_URL is required"):
        build_gateway(Route(name="delivery", url=UPSTREAM, prefix="/"))


@pytest.mark.parametrize("raw", [None, "", "   "])
def test_a_missing_gateway_slug_refuses_to_start(monkeypatch, raw):
    """The slug is the only thing saying whose bundle this gateway fetches.

    Defaulting it is the expensive failure rather than the loud one. Rail Center
    resolves the credential before it reads the query, so on `RAIL_AUTH_MODE=none`
    — where the credential names nothing — a made-up slug is answered rather than
    rejected, and this gateway enforces another gateway's bindings, posture and
    fallback against its own traffic. Whitespace counts as missing for the reason
    every other required variable does: it is an operator who meant to set it.
    """
    monkeypatch.setenv("RAIL_CENTER_URL", "http://rail-center.test")
    if raw is None:
        monkeypatch.delenv("RAIL_GATEWAY_SLUG", raising=False)
    else:
        monkeypatch.setenv("RAIL_GATEWAY_SLUG", raw)

    with pytest.raises(RuntimeError, match="RAIL_GATEWAY_SLUG is required"):
        gateway_slug()
    with pytest.raises(RuntimeError, match="RAIL_GATEWAY_SLUG is required"):
        build_gateway(Route(name="delivery", url=UPSTREAM, prefix="/"))


@pytest.mark.parametrize("url", ["http://", "http://user:pw@", "https://"])
def test_a_rail_center_url_with_no_host_refuses_to_start(monkeypatch, url):
    monkeypatch.setenv("RAIL_CENTER_URL", url)

    with pytest.raises(RuntimeError, match="RAIL_CENTER_URL names no host"):
        build_gateway(Route(name="delivery", url=UPSTREAM, prefix="/"))


def test_a_rail_center_url_with_no_scheme_keeps_its_credential_out_of_the_error(
    monkeypatch,
):
    """The other half of the same refusal, carrying a secret. Forgetting the
    scheme is the whole of what it takes: `svcuser:pw@host/` parses as a scheme
    with the rest as path, so there is no host and no netloc either — and a
    redaction that rebuilds from the netloc has nothing to strip and hands back
    the password whole, into the stderr of a failed start."""
    monkeypatch.setenv(
        "RAIL_CENTER_URL", "svcuser:s3cret-rc-password@rail-center.test/"
    )

    with pytest.raises(RuntimeError) as raised:
        build_gateway(Route(name="delivery", url=UPSTREAM, prefix="/"))

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
        RuntimeError, match="upstream 'delivery' is not a URL that can be parsed"
    ):
        build_gateway(Route(name="delivery", url="http://[::1", prefix="/"))


def test_an_unparseable_rail_center_url_names_the_control_plane(monkeypatch):
    """The other half of the same helper. Named separately because a message
    hardcoded to either variable passes the case for that one."""
    monkeypatch.setenv("RAIL_CENTER_URL", "http://[::1")

    with pytest.raises(
        RuntimeError, match="RAIL_CENTER_URL is not a URL that can be parsed"
    ):
        build_gateway(Route(name="delivery", url=UPSTREAM, prefix="/"))


def test_an_unparseable_url_carrying_no_credential_keeps_its_diagnostic(monkeypatch):
    """The common case of that branch, and the one the redactor can spoil. With
    no userinfo to remove, `str.replace("", "***")` would put the marker between
    every character of the message — `***I***n***v***a***l***i***d***…` — and
    the operator loses the half of it that says what they mistyped."""
    monkeypatch.setenv("RAIL_CENTER_URL", "http://[::1")

    with pytest.raises(RuntimeError) as raised:
        build_gateway(Route(name="delivery", url=UPSTREAM, prefix="/"))

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
    monkeypatch.setenv(
        "RAIL_CENTER_URL",
        f"{prefix}svcuser:s3cret-rc-password@rail\u2100center.test/",
    )

    with pytest.raises(RuntimeError) as raised:
        build_gateway(Route(name="delivery", url=UPSTREAM, prefix="/"))

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
    monkeypatch.setenv(
        "RAIL_CENTER_URL",
        f"http://svcuser:s3cret-rc-password@rail\u2100center.test{tail}",
    )

    with pytest.raises(RuntimeError) as raised:
        build_gateway(Route(name="delivery", url=UPSTREAM, prefix="/"))

    message = str(raised.value)
    assert "RAIL_CENTER_URL is not a URL that can be parsed" in message
    assert "s3cret-rc-password" not in message
    assert "svcuser" not in message


def test_the_routes_file_is_read_before_the_control_plane(monkeypatch, tmp_path):
    """An operator who has configured neither should be told about the one they
    would fix first. A gateway with no upstreams forwards nothing whatever its
    control plane says, so that is the first refusal."""
    monkeypatch.setenv("RAIL_GATEWAY_ROUTES_FILE", str(tmp_path / "absent.yaml"))
    monkeypatch.delenv("RAIL_CENTER_URL", raising=False)

    with pytest.raises(RoutesError, match="cannot read"):
        build_app()


def test_a_credential_that_cannot_be_sent_is_refused_at_startup(monkeypatch):
    """Resolved while `build_gateway` runs, not at the first fetch. Deferred, a
    mistyped secret would surface as a bundle that never arrives, long after
    the deploy that caused it and with nothing naming the cause."""
    monkeypatch.setenv("RAIL_CENTER_URL", "http://rail-center.invalid")
    monkeypatch.setenv("RAIL_AUTH_MODE", "bearer")
    monkeypatch.setenv("RAIL_AUTH_TOKEN", "line-one\nline-two")

    with pytest.raises(AuthConfigurationError, match="RAIL_AUTH_TOKEN holds U\\+000A"):
        build_gateway(Route(name="delivery", url=UPSTREAM, prefix="/"))


def test_an_unreadable_refresh_interval_is_refused_at_startup(monkeypatch):
    """Same reasoning, same place. `refresh_seconds` raises on a value that is
    not a number, and it has to be called somewhere a caller sees it.

    The auth variables are cleared because `_holder_from_environment` reaches
    `auth_headers()` first: either of them set in the shell running the suite
    raises before the interval is ever read, and this case then fails on
    correct code with a message about a credential. `.env.example` documents
    both, so a contributor's shell is exactly where they turn up.
    """
    monkeypatch.setenv("RAIL_CENTER_URL", "http://rail-center.invalid")
    monkeypatch.delenv("RAIL_AUTH_MODE", raising=False)
    monkeypatch.delenv("RAIL_AUTH_TOKEN", raising=False)
    monkeypatch.setenv("RAIL_GATEWAY_BUNDLE_REFRESH_SECONDS", "often")

    with pytest.raises(RuntimeError, match="must be an integer"):
        build_gateway(Route(name="delivery", url=UPSTREAM, prefix="/"))


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
    monkeypatch.setenv("RAIL_CENTER_URL", "http://user:s3cret@rail-center.invalid")
    monkeypatch.setenv("RAIL_AUTH_MODE", "bearer")
    monkeypatch.setenv("RAIL_AUTH_TOKEN", "configured-token")

    with pytest.raises(RuntimeError, match="only one of them can be sent"):
        build_gateway(Route(name="delivery", url=UPSTREAM, prefix="/"))


# --- RAIL_PLUGIN_ENABLED: is RailXia installed here ------------------------
#
# RC-312 replaced `RAIL_TICKET_MODE` with this. It answers *is RailXia installed
# on this deployment* and nothing else; what to do with a call arrives in the
# bundle. `plugin_enabled()` is the one reader nothing else in this suite
# reaches — every other test injects `plugin=` into `build_app`, which skips it
# — so its default, its refusals and its case folding are pinned here or
# nowhere.


def test_an_unset_plugin_flag_is_false(monkeypatch):
    """A gateway nobody gave RailXia configuration needs no variable at all.

    The danger in this default is a dropped line unenrolling a gateway that was
    enforcing an hour ago — and that is the case the contradiction refusal
    below catches, because it is exactly the case with `RAIL_CENTER_URL` set.
    """
    monkeypatch.delenv("RAIL_PLUGIN_ENABLED", raising=False)
    for name in ("RAIL_CENTER_URL", "RAIL_AUTH_MODE", "RAIL_AUTH_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    assert plugin_enabled() is False


@pytest.mark.parametrize("raw", ["", "   ", "\t\n"])
def test_a_blank_plugin_flag_is_read_as_unset(monkeypatch, raw):
    monkeypatch.setenv("RAIL_PLUGIN_ENABLED", raw)
    for name in ("RAIL_CENTER_URL", "RAIL_AUTH_MODE", "RAIL_AUTH_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    assert plugin_enabled() is False


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("true", True),
        ("TRUE", True),
        ("True", True),
        (" true ", True),
        ("false", False),
        ("FALSE", False),
        ("False", False),
    ],
)
def test_the_plugin_flag_is_read_case_insensitively(monkeypatch, raw, expected):
    """One question, asked of two components, so both must resolve the same set.

    The proxy in front reads its own flag through `.strip().lower()`. A gateway
    matching exactly would refuse to start on the `TRUE` its proxy resolved
    happily — the zone configured correctly in front, and the component behind
    it refusing to boot.
    """
    monkeypatch.setenv("RAIL_PLUGIN_ENABLED", raw)
    # Cleared for the `false` half: Rail Center configuration beside a disabled
    # plugin is its own refusal, and it would fire before the value was read.
    for name in ("RAIL_CENTER_URL", "RAIL_AUTH_MODE", "RAIL_AUTH_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    assert plugin_enabled() is expected


@pytest.mark.parametrize("raw", ["ture", "yes", "1", "on", "plugin", "none"])
def test_an_unrecognised_plugin_flag_refuses_to_start(monkeypatch, raw):
    """Refused rather than read as false, and that direction is the point.

    A component that read `ture` as *off* would unenrol on a typo — losing
    enforcement silently, which is the one outcome no misconfiguration here is
    allowed to produce.
    """
    monkeypatch.setenv("RAIL_PLUGIN_ENABLED", raw)
    with pytest.raises(PluginConfigError, match="RAIL_PLUGIN_ENABLED must be one of"):
        plugin_enabled()


def test_a_refused_plugin_flag_names_what_the_operator_wrote(monkeypatch):
    """The folded form is what is matched; the raw one is what is reported, so a
    value refused for some reason other than its case reads back to whoever set
    it."""
    monkeypatch.setenv("RAIL_PLUGIN_ENABLED", "Plugged")
    with pytest.raises(PluginConfigError, match="Plugged"):
        plugin_enabled()


@pytest.mark.parametrize("raw", ["plugin", "none", "enforce", "observe"])
def test_a_leftover_ticket_mode_refuses_to_start_and_says_what_replaced_it(
    monkeypatch, raw
):
    """The deliberate break, and the reason it is a break rather than a silent
    removal.

    `RAIL_TICKET_MODE` carried a posture, then carried enrolment, and now
    carries nothing. A deployment still setting it believes it is configuring
    something — so ignoring it would leave an operator reading a line that does
    nothing, which is the failure this whole change exists to end. The message
    has to send them somewhere, or they will set it back.
    """
    monkeypatch.setenv("RAIL_TICKET_MODE", raw)
    monkeypatch.setenv("RAIL_PLUGIN_ENABLED", "true")
    with pytest.raises(PluginConfigError, match="RAIL_TICKET_MODE is no longer read"):
        plugin_enabled()
    with pytest.raises(PluginConfigError, match="RAIL_PLUGIN_ENABLED"):
        plugin_enabled()
    with pytest.raises(PluginConfigError, match="enforcement.mode"):
        plugin_enabled()


@pytest.mark.parametrize(
    "name", ["RAIL_CENTER_URL", "RAIL_AUTH_MODE", "RAIL_AUTH_TOKEN"]
)
def test_rail_center_configuration_beside_a_disabled_plugin_refuses_to_start(
    monkeypatch, name
):
    """What makes defaulting to `false` safe.

    The dangerous case is a dropped flag on a deployment that was enrolled — and
    that deployment is, by construction, the one still carrying the variables
    that point at Rail Center. Refusing there stops the component instead of
    unenrolling it, while a deployment with nothing configured boots as the
    plain gateway it is.
    """
    monkeypatch.delenv("RAIL_PLUGIN_ENABLED", raising=False)
    for other in ("RAIL_CENTER_URL", "RAIL_AUTH_MODE", "RAIL_AUTH_TOKEN"):
        monkeypatch.delenv(other, raising=False)
    monkeypatch.setenv(name, "set-to-something")

    with pytest.raises(PluginConfigError, match=name) as raised:
        plugin_enabled()
    assert "RAIL_PLUGIN_ENABLED" in str(raised.value)


@pytest.mark.parametrize("raw", ["none", "NONE", " none "])
def test_an_auth_mode_of_none_beside_a_disabled_plugin_boots(monkeypatch, raw):
    """`none` asserts no enrolment, so it cannot contradict a plugin that is off.

    It is `RAIL_AUTH_MODE`'s own default and names *no credential* — the state
    of every gateway with no control plane — so a platform template that spells
    the default out, or a zone setting one auth mode across every component, is
    not a deployment anyone enrolled. Refusing there would stop a plain gateway
    over a line that asserts nothing, and offer it a remedy that then demands
    `RAIL_CENTER_URL`.

    Case and surrounding space are not the operator's problem: `auth_headers`
    reads this variable through `.strip().lower()`, so a gateway refusing on
    `NONE` would refuse a value its own auth layer resolves.
    """
    monkeypatch.delenv("RAIL_PLUGIN_ENABLED", raising=False)
    monkeypatch.delenv("RAIL_CENTER_URL", raising=False)
    monkeypatch.delenv("RAIL_AUTH_TOKEN", raising=False)
    monkeypatch.setenv("RAIL_AUTH_MODE", raw)

    assert plugin_enabled() is False


def test_an_auth_mode_of_none_beside_a_rail_center_url_still_refuses(monkeypatch):
    """The decisive variable is what catches a deployment that was enrolled.

    Admitting `none` loses nothing because a gateway that really polls a Rail
    Center has a URL pointing at one, and that is refused whatever the auth mode
    says. The refusal names the URL and not the mode, so an operator is sent to
    the line that actually contradicts the flag.
    """
    monkeypatch.delenv("RAIL_PLUGIN_ENABLED", raising=False)
    monkeypatch.delenv("RAIL_AUTH_TOKEN", raising=False)
    monkeypatch.setenv("RAIL_AUTH_MODE", "none")
    monkeypatch.setenv("RAIL_CENTER_URL", "http://rail-center.test")

    with pytest.raises(PluginConfigError) as raised:
        plugin_enabled()
    message = str(raised.value)
    assert "RAIL_CENTER_URL" in message
    assert "RAIL_AUTH_MODE" not in message


def test_the_contradiction_refusal_names_every_variable_it_found(monkeypatch):
    """One line naming all of them, rather than one refusal per restart."""
    monkeypatch.setenv("RAIL_PLUGIN_ENABLED", "false")
    monkeypatch.setenv("RAIL_CENTER_URL", "http://rail-center.test")
    monkeypatch.setenv("RAIL_AUTH_MODE", "bearer")
    monkeypatch.delenv("RAIL_AUTH_TOKEN", raising=False)

    with pytest.raises(PluginConfigError) as raised:
        plugin_enabled()
    message = str(raised.value)
    assert "RAIL_CENTER_URL" in message and "RAIL_AUTH_MODE" in message
    assert "RAIL_AUTH_TOKEN" not in message


def test_an_enabled_plugin_beside_rail_center_configuration_is_the_normal_case(
    monkeypatch,
):
    monkeypatch.setenv("RAIL_PLUGIN_ENABLED", "true")
    monkeypatch.setenv("RAIL_CENTER_URL", "http://rail-center.test")
    assert plugin_enabled() is True


# --- the wire from the variable to the two entry points ---------------------
#
# The block above pins `plugin_enabled()` and the blocks below pin what each
# entry point does once it has an answer. Between them sits the wire: every
# other test in this suite injects `plugin=`, so unless something here builds
# without it, both entry points can stop reading the environment entirely and
# nothing says so. What that would ship is an unconfigured gateway defaulting to
# *enrolled* and both startup refusals skipped at the one path a deployment
# actually takes.


def _unenrolled(monkeypatch):
    """An environment describing a gateway nobody gave RailXia."""
    for name in (
        "RAIL_PLUGIN_ENABLED",
        "RAIL_TICKET_MODE",
        "RAIL_CENTER_URL",
        "RAIL_AUTH_MODE",
        "RAIL_AUTH_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)


def test_build_gateway_takes_the_flag_from_the_environment(monkeypatch, caplog):
    """No variable at all is a plain gateway, and `RAIL_CENTER_URL` is not read.

    An entry point that stopped asking would default this deployment to enrolled
    and then demand a control plane it was never given.
    """
    _unenrolled(monkeypatch)

    with caplog.at_level(logging.INFO, logger="gateway"):
        build_gateway(Route(name="delivery", url=UPSTREAM, prefix="/"))

    assert "RAIL_PLUGIN_ENABLED=false" in "\n".join(
        record.getMessage() for record in caplog.records
    )


def test_build_gateway_refuses_a_leftover_ticket_mode_from_the_environment(
    monkeypatch,
):
    """The refusal has to fire at the real startup path, not only in isolation.

    A variable an operator believes configures a posture, silently ignored by
    the one function a deployment calls, is the failure the split exists to end.
    """
    _unenrolled(monkeypatch)
    monkeypatch.setenv("RAIL_TICKET_MODE", "enforce")

    with pytest.raises(PluginConfigError, match="RAIL_TICKET_MODE is no longer read"):
        build_gateway(Route(name="delivery", url=UPSTREAM, prefix="/"))


def test_build_app_takes_the_flag_from_the_environment(monkeypatch):
    """The same wire at the other entry point, and it is the one uvicorn calls.

    With the plugin off the application is served bare — no wrapper, no holder,
    no slug — so a bare app is the observable answer to *which flag did it read*.
    """
    _unenrolled(monkeypatch)

    app = build_app([Route(name="delivery", url=UPSTREAM, prefix="/")])

    assert not isinstance(app, _Enforcement)


def test_build_app_refuses_a_leftover_ticket_mode_from_the_environment(monkeypatch):
    _unenrolled(monkeypatch)
    monkeypatch.setenv("RAIL_TICKET_MODE", "plugin")

    with pytest.raises(PluginConfigError, match="RAIL_TICKET_MODE is no longer read"):
        build_app()


def test_build_app_refuses_rail_center_configuration_beside_a_disabled_plugin(
    monkeypatch,
):
    """The dangerous case, refused where a deployment meets it.

    A dropped `RAIL_PLUGIN_ENABLED` on a gateway that was enforcing an hour ago
    still has the URL it polled; an entry point that skipped the check would
    unenrol it silently and forward every request.
    """
    _unenrolled(monkeypatch)
    monkeypatch.setenv("RAIL_CENTER_URL", "http://rail-center.test")

    with pytest.raises(PluginConfigError, match="RAIL_CENTER_URL"):
        build_app()


# --- the startup line, and the posture line --------------------------------
#
# Two lines now, written at two moments. `build_gateway` writes the plugin line
# at INFO on every start; the posture line is what a poll has to say when the
# bundle moves. `test_readiness.py`'s control-plane-down case filters the banner
# out by `RAIL_PLUGIN_ENABLED=` prefix, so what these say is pinned here.


@pytest.mark.parametrize("enabled", [True, False])
def test_each_startup_line_names_the_state_it_describes(enabled):
    """A line naming the wrong state is worse than no line: it is the log an
    operator checks *instead of* sending a request."""
    spelled = "true" if enabled else "false"
    assert describe_plugin(enabled).startswith(f"RAIL_PLUGIN_ENABLED={spelled} — ")


def test_the_two_startup_lines_do_not_repeat_each_other():
    assert describe_plugin(False) != describe_plugin(True)


def test_the_enabled_line_promises_nothing_about_traffic():
    """The line an enrolled deployment writes, and the claim it must not make.
    What this gateway does to a request is the bundle's to say and is not known
    at start-up, so a start-up line naming a posture would be a guess an
    operator reads as a fact."""
    line = describe_plugin(True)

    assert "polls Rail Center" in line
    assert "judges nothing" in line and "unready" in line
    assert "403" not in line and "blocked" not in line


def test_the_disabled_line_says_there_is_no_control_plane():
    """The flag means *RailXia is not installed here*, not "do not enforce". The
    second half matters as much: an operator debugging a control plane this
    gateway is not talking to needs to be told it never will."""
    line = describe_plugin(False)

    assert "not installed" in line
    assert "forwards every request" in line
    assert "fetches no policy bundle" in line


@pytest.mark.parametrize("enforcement", ENFORCEMENTS)
def test_each_posture_line_names_the_enforcement_it_describes(enforcement):
    assert describe_enforcement(enforcement, "block", told=True).startswith(
        f"enforcement={enforcement} — "
    )


def test_the_enforce_line_says_the_traffic_it_refuses():
    """Both refusals named, and the claim this line used to carry — that
    enforcement is not implemented and the mode behaves as observe — may not
    come back."""
    line = describe_enforcement("enforce", "block", told=True)

    assert "403" in line and "503" in line
    assert "reported to Rail Center" in line
    assert "nothing is blocked" not in line
    assert "not implemented" not in line


def test_the_observe_line_says_nothing_is_blocked():
    line = describe_enforcement("observe", "block", told=True)

    assert "nothing is blocked" in line
    assert "403" not in line and "503" not in line
    assert "refus" not in line


def test_the_none_posture_line_says_it_keeps_polling():
    """The half that is easy to leave out and is the whole of RC-312 on this
    side: a gateway told `none` is still listening, so an operator can move it
    back without a redeploy."""
    line = describe_enforcement("none", "block", told=True)

    assert "forwarded" in line
    assert "keeps polling" in line
    assert "403" not in line and "503" not in line


@pytest.mark.parametrize("enforcement", ["none", "observe"])
def test_the_fallback_is_named_only_where_it_decides_something(enforcement):
    """It is consulted at `enforce` and nowhere else, so a line mentioning it
    anywhere else invites an operator to think it applies there."""
    assert "fallback" not in describe_enforcement(enforcement, "pass", told=True)


def test_an_untold_posture_says_rail_center_named_none_rather_than_chose_none():
    """Silence is not a decision, and the line may not report it as one.

    A bundle carrying no `enforcement` resolves to the same `none` as one
    naming `none`, so this is the only place the two states can be told
    apart. The contract refuses to name a safe universal reading of the
    absence, which makes "Rail Center says judge nothing" a claim about a
    control plane that said nothing at all — and the operator it misleads is
    the one whose gateway has just stopped judging anything.
    """
    line = describe_enforcement("none", "block", told=False)

    assert line.startswith("enforcement=none — ")
    assert "Rail Center says" not in line
    assert "has said nothing" in line
    assert "no posture" in line
    assert "keeps polling" in line
    # What it must not have acquired: the fallback decides nothing here either.
    assert "fallback" not in line
    assert "403" not in line and "503" not in line


def test_the_told_and_untold_none_lines_are_not_each_other():
    """Both resolve to `none`/`block` and they are different states.

    Two lines that differed only in wording would be a distinction nothing
    downstream could act on; `_refresh_once` dedupes on the rendered line, so
    equal text here is a Rail Center upgrade that never reports itself.
    """
    assert describe_enforcement("none", "block", told=False) != describe_enforcement(
        "none", "block", told=True
    )


def test_an_untold_posture_reads_the_same_whatever_fallback_it_resolved_to():
    """The fallback is not consulted at `none`, told or untold."""
    assert describe_enforcement("none", "block", told=False) == describe_enforcement(
        "none", "pass", told=False
    )


def test_the_enforce_line_says_what_each_fallback_does_to_an_unbound_endpoint():
    """The pair whose meaning RC-312 corrected, so the two lines must differ in
    the direction the correction went: `pass` is not "unjudged"."""
    blocked = describe_enforcement("enforce", "block", told=True)
    passed = describe_enforcement("enforce", "pass", told=True)

    assert "fallback=block" in blocked and "without consulting the chain" in blocked
    assert "fallback=pass" in passed and "judged by the whole chain" in passed
    assert "unjudged" not in passed
