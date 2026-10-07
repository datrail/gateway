"""What every interface reads from the environment to reach Rail Center.

The port, the Rail Center URL and its credential, the gateway's slug, and the
bundle holder built from them. Each is refused at startup in the same words
whichever interface reads it. What an interface serves stays in that interface.
"""

import base64
import os
from urllib.parse import unquote, urlsplit, urlunsplit

from gateway.core.auth import auth_headers
from gateway.core.bundle.client import BundleHolder, refresh_seconds

DEFAULT_PORT = 8080


def _required(name: str) -> str:
    """Read a variable that has no sensible default.

    Raising here rather than defaulting is deliberate: a gateway pointed at
    nothing forwards nothing, and it would report healthy while doing it.
    """
    value = (os.environ.get(name) or "").strip()
    if not value:
        raise RuntimeError(f"{name} is required and is unset or empty")
    return value


def _checked_url(name: str, url: str) -> str:
    """`url`, once it is one that names somewhere to go.

    Both variables this validates are addresses the process cannot function
    without and cannot discover to be wrong: `http://` and `http://user:pw@`
    parse, and a gateway built on either starts and answers `/health` while
    reaching nothing. The upstream one forwards nothing; the Rail Center one
    fetches no bundle ever, and reports it in the log as a control plane that
    is down — a fault an operator would look for in the wrong place entirely.
    """
    try:
        hostname = urlsplit(url).hostname
    except ValueError as exc:
        # An unclosed IPv6 bracket raises here, before the host check below —
        # a bare traceback that never names the variable the operator set.
        # Through `_credential_free` and not `_safe_to_log`: the message being
        # reported is the one `urlsplit` raised, so anything that parses to
        # redact would raise it again.
        raise RuntimeError(
            f"{name} is not a URL that can be parsed: {_credential_free(str(exc), url)}"
        ) from None
    if not hostname:
        raise RuntimeError(f"{name} names no host: {_safe_to_log(url)}")
    return url


def port() -> int:
    """The port to listen on.

    Stripped before the default is applied, so a variable set to whitespace is
    read the same way `_required` reads one — as an operator who meant to set
    it — rather than reaching `int()` and reporting an empty value back.
    """
    raw = (os.environ.get("RAIL_GATEWAY_PORT") or "").strip() or str(DEFAULT_PORT)
    try:
        value = int(raw)
    except ValueError:
        raise RuntimeError(
            f"RAIL_GATEWAY_PORT must be an integer, got: {raw}"
        ) from None
    if not 1 <= value <= 65535:
        raise RuntimeError(
            f"RAIL_GATEWAY_PORT must be between 1 and 65535, got: {value}"
        )
    return value


def rail_center_from_environment() -> tuple[str, dict[str, str]]:
    """Where Rail Center is, and what this gateway presents to it.

    One pair, resolved once, for both callers that reach the control plane: the
    bundle holder and the denial reporter. Resolving it twice would let the two
    disagree — a gateway fetching policy as one identity and reporting denials
    as another is a state nothing would report and an operator could not read
    off either side.

    `RAIL_CENTER_URL` goes through `_split_credential` for the reason the
    upstream URL does and one more: httpx derives `BasicAuth` from a URL's
    userinfo and **overwrites** the `Authorization` header it was given, so a
    `user:password@` left in this one silently displaces the configured bearer
    token and calls the control plane as somebody else.
    """
    url, from_url = _split_credential(
        _checked_url("RAIL_CENTER_URL", _required("RAIL_CENTER_URL"))
    )
    configured = auth_headers()
    if from_url and "Authorization" in configured:
        raise RuntimeError(
            "RAIL_CENTER_URL carries a credential and RAIL_AUTH_MODE configures "
            "one; only one of them can be sent, so set exactly one"
        )
    return url, {**from_url, **configured}


def build_holder() -> BundleHolder:
    """The policy bundle holder a deployment's variables describe.

    Every one of them is read here rather than inside the holder, so the whole
    of what an operator can misconfigure is refused in one place at startup:
    `auth_headers` raises on a credential that cannot go in a header, and
    `refresh_seconds` on an interval that is not a number.
    """
    url, headers = rail_center_from_environment()
    return BundleHolder(
        url, headers, gateway_slug(), interval_seconds=refresh_seconds()
    )


def gateway_slug() -> str:
    """`RAIL_GATEWAY_SLUG` — which gateway this is, and whose bundle it fetches.

    **Not the data source's slug**, and the distinction is the whole reason this
    variable exists. A gateway fronts several data sources and a data source may
    sit behind several gateways, so no single data source slug can identify the
    component; the bundle is built for a gateway, carrying that gateway's
    bindings, posture and fallback (design §4.4, §4.5).

    Required whenever the plugin is enabled, and read nowhere else — a gateway
    with no control plane fetches nothing and has nothing to name itself to.
    """
    return _required("RAIL_GATEWAY_SLUG")


def _split_credential(url: str) -> tuple[str, dict[str, str]]:
    """Move any `user:password@` out of the URL and into an Authorization header.

    Not cosmetic. httpx names the URL it called in its error text — `Client
    error '401 Unauthorized' for url '<url>'` — and fastmcp puts that string
    into the JSON-RPC error it returns to the caller. With the credential in
    the URL, an ordinary upstream 401 hands it to an unauthenticated agent, and
    a stale upstream key turns every call into a disclosure of it. The error
    boundary below cannot reach this one: the failure happens while the proxy
    is opening its session, before any message it wraps.

    The credential still travels, on the same request, in the header where a
    credential belongs.
    """
    parsed = urlsplit(url)
    if not parsed.username and not parsed.password:
        return url, {}
    credential = f"{unquote(parsed.username or '')}:{unquote(parsed.password or '')}"
    encoded = base64.b64encode(credential.encode()).decode()
    host = parsed.netloc.rsplit("@", 1)[-1]
    return (
        urlunsplit(parsed._replace(netloc=host)),
        {"Authorization": f"Basic {encoded}"},
    )


def _credential_free(text: str, url: str) -> str:
    """`text`, with any credential `url` carries taken back out of it.

    The redaction every message about a rejected URL is built on. `urlsplit`
    raises `ValueError("netloc '<netloc>' contains invalid characters under
    NFKC normalization")` for a host that normalises into a delimiter, and it
    quotes that netloc **whole, userinfo included** — so interpolating the
    exception into a startup error writes a live control-plane password to
    stderr, where the container's log collector and the CI log of every job
    that runs the image both keep it. Parsing is no help on that path: it is
    the branch reached because parsing raised. So the authority is found by
    string surgery on the raw value instead, and whatever precedes its last
    `@` is removed wherever the message repeats it.

    Removed together with that `@`, and replaced by a marker that keeps one.
    The userinfo on its own is a short, ordinary string — `svc`, `api` — and
    replacing every occurrence of it overwrote the host and the path as well:
    `https://svc@svc.default.svc.cluster.local:8080/mcp` came out as
    `https://***.default.***.cluster.local:8080/mcp`, losing the half of the
    line an operator reads it for. A credential is only a credential where it
    sits in front of an `@`, so that is what is matched.

    An authority does not need `scheme://` in front of it, and keying off that
    separator finds nothing in exactly the malformed values these messages are
    written for: `//user:pw@host/`, and the `user:pw@host/` of an operator who
    forgot the scheme, both carry one.
    """
    _, separator, rest = url.partition("://")
    authority = rest if separator else url.removeprefix("//")
    for delimiter in "/?#":
        authority = authority.partition(delimiter)[0]
    userinfo = authority.rpartition("@")[0]
    return text.replace(f"{userinfo}@", "***@") if userinfo else text


def _safe_to_log(url: str) -> str:
    """Where the gateway points, with every part that can carry a secret gone.

    An upstream's `url` in the routes file can legitimately carry
    `user:password@`, and a hosted MCP endpoint commonly carries `?api_key=`.
    The line naming it is written on every start, once per upstream, so both
    would reach stdout and whatever collects it.

    Rebuilt rather than selectively rewritten. Clearing the authority alone left
    the query untouched; reassembling from `hostname` and `port` dropped the
    brackets an IPv6 literal needs and raised on a port that is not a number —
    a redaction helper crashing on the value it was handed being the worst
    shape available. Scheme, host and path are what an operator is reading for.

    The credential comes out through `_credential_free` first, on the raw
    string, because the rebuild below only redacts a URL that has an authority
    to rebuild and `scheme://` is what tells `urlsplit` there is one. This is
    also called on the value `_checked_url` rejects for naming no host, and
    `user:pw@host/` — an operator who forgot the scheme — parses as a scheme
    with the rest as path: an empty netloc, from which the rebuild strips
    nothing and returns the password whole.
    """
    parsed = urlsplit(_credential_free(url, url))
    netloc = parsed.netloc.rsplit("@", 1)[-1]
    dropped = [
        n for n, v in (("query", parsed.query), ("fragment", parsed.fragment)) if v
    ]
    suffix = f" ({' and '.join(dropped)} omitted)" if dropped else ""
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", "")) + suffix
