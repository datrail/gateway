"""Which upstreams this gateway fronts, and where each one listens.

One gateway fronts several data sources, and this file is where they are named:
the same file the proxy reads, with one field added.

**The file carries no slugs, and that is the design rather than an omission.**
An entry's `name` is a label: it appears in logs and in nothing else. Rail
Center's data source slugs do not appear here at all, because a gateway fronts
several data sources and a data source may sit behind several gateways, so
nothing local can name the relationship. What the gateway composes from a
request is a *comparable* key with no slug in it, and what it compares against
is a bundle key with the slug stripped off — see `gateway.endpoint`.

**`prefix` is the gateway's own field**, and the proxy has no use for one. It is
where this gateway listens for that upstream, and it is the only thing that
decides routing: two upstreams that both serve `/mcp` are told apart by the
prefix in front, never by anything in the message. Overlapping prefixes are
refused at startup for that reason — a request matching two routes has no answer
this gateway could give.

The prefix is **removed** before the request is forwarded and before a key is
composed, and travels on as `X-Forwarded-Prefix` for an upstream that needs to
build absolute URLs. It must not enter the endpoint key: Rail Center stores one
row per endpoint, and the same MCP server behind two gateways mounted at
different prefixes would otherwise produce two keys for one row.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import yaml

log = logging.getLogger("gateway")

#: Where the routes file is, unless the environment says otherwise. The image
#: bakes a path that holds no file, so a container started without one mounted
#: stops here rather than coming up fronting nothing.
DEFAULT_ROUTES_FILE: Final[Path] = Path("/etc/rail/routes.yaml")

#: The file shape this reader understands, as a major version. **The same rule
#: the proxy applies to the same file**, deliberately: an operator writes one
#: document for two components and should not have to learn two rules for it.
#:
#: It is not quite the rule `gateway.bundle.validate` applies to the bundle's
#: own `schema_version`, and the difference is the documents rather than an
#: oversight. This file is local and hand-written, so an absent version is a
#: file that predates the field and is warned about; a bundle arrives from a
#: control plane that always sends one, so silence there is drift and is
#: refused.
CONFIG_SCHEMA_MAJOR: Final[int] = 1

#: What an entry may carry. Anything else is said out loud and ignored, for the
#: reason the proxy gives: `headers:` is how every mainstream MCP client config
#: spells an upstream credential, so an operator will write it, and a gateway
#: that dropped it silently would 401 every call to that upstream with nothing
#: anywhere saying why. Whether to *honour* it is an open scope question.
ENTRY_KEYS: Final[frozenset[str]] = frozenset({"name", "url", "prefix"})


class RoutesError(RuntimeError):
    """The routes file cannot be honoured. Fatal at startup, by design."""


@dataclass(frozen=True)
class Route:
    """One upstream, and where this gateway listens for it."""

    #: An operator's label for the upstream. Unique, and carried into log lines
    #: so a message about a route names something they wrote.
    name: str
    #: Where the upstream actually is.
    url: str
    #: The path this gateway serves it under, always starting with `/` and never
    #: ending with one — `/` itself being the single-upstream case, where the
    #: gateway listens at its root and strips nothing.
    prefix: str

    @property
    def strips(self) -> str:
        """The leading string removed from a path routed here.

        Empty for the root prefix, so that stripping is the same operation for
        every route and `/mcp` does not become the empty string under `/`.
        """
        return "" if self.prefix == "/" else self.prefix


def routes_file() -> Path:
    """`RAIL_GATEWAY_ROUTES_FILE`, or the baked default."""
    raw = (os.environ.get("RAIL_GATEWAY_ROUTES_FILE") or "").strip()
    return Path(raw) if raw else DEFAULT_ROUTES_FILE


def _check_schema_version(path: Path, raw: Any) -> None:
    """Refuse a routes file this gateway cannot read whole.

    Absent is read as the supported major and warned about, because every file
    written before the field existed omits it and stopping those costs an
    operator a restart for nothing: a file with no version is a file with no
    field this reader is missing. The warning is what gets the line added before
    the format does move.
    """
    if raw is None:
        log.warning(
            "%s has no schema_version; reading it as %d.0 — add "
            '`schema_version: "%d.0"`',
            path,
            CONFIG_SCHEMA_MAJOR,
            CONFIG_SCHEMA_MAJOR,
        )
        return
    # Quoted in the example, so `1.0` unquoted arrives as a float and `1` as an
    # int. Both are what an operator meant; neither is refused over its type.
    text = str(raw).strip()
    parts = text.split(".")
    # Every part, not only the major: `1.x` has a major this gateway reads and
    # is still not a version, and honouring it would mean honouring a file whose
    # version nobody can compare to the next one. A third part is not refused —
    # `1.0.0` is major 1 by any reading, and the major is the whole comparison.
    #
    # ASCII digits, not `isdigit()`: that is true of superscripts, which `int`
    # then rejects with a `ValueError` nobody catches, and of other scripts'
    # decimal digits, which `int` accepts — so `١.0` would be served as major 1.
    # A version in this file is written in the digits the rest of it is.
    if not all(part.isascii() and part.isdigit() for part in parts):
        raise RoutesError(
            f"{path}: schema_version {text!r} is not a version; this gateway "
            f"reads {CONFIG_SCHEMA_MAJOR}.x"
        )
    if int(parts[0]) != CONFIG_SCHEMA_MAJOR:
        raise RoutesError(
            f"{path}: schema_version {text!r} is a format this gateway does not "
            f"read; it reads {CONFIG_SCHEMA_MAJOR}.x"
        )


def _prefix(path: Path, name: str, raw: Any) -> str:
    """One entry's `prefix`, normalised to the one form everything else assumes.

    Absent is `/`, which is the single-upstream deployment and the shape every
    gateway had before this file existed.

    A trailing slash is removed so that `/delivery/` and `/delivery` are one
    route rather than two that overlap, and a missing leading slash is supplied
    because `delivery` is unambiguous about what it meant. Both are normalised
    rather than refused: they are the same intent spelled differently, and a
    startup refusal over a slash is a worse outcome than reading it.
    """
    if raw is None:
        return "/"
    if not isinstance(raw, str):
        raise RoutesError(
            f"{path}: upstream '{name}' has a prefix that is not text "
            f"({type(raw).__name__})"
        )
    text = raw.strip()
    if not text or text == "/":
        return "/"
    if not text.startswith("/"):
        text = "/" + text
    text = text.rstrip("/")
    # Refused rather than normalised, because there is no single thing it could
    # have meant: a path this gateway would never match is a route that silently
    # serves nothing, which is the failure the whole file exists to make visible.
    if "//" in text or any(part in ("", ".", "..") for part in text[1:].split("/")):
        raise RoutesError(f"{path}: upstream '{name}' has an unusable prefix {raw!r}")
    return text


def _refuse_overlaps(path: Path, routes: list[Route]) -> None:
    """Refuse a file where one request could match two routes.

    **An overlap has no right answer, which is why it stops the process rather
    than resolving by longest-match.** `/delivery` and `/delivery/mcp` both
    claim `/delivery/mcp/...`; picking the longer one is a rule an operator did
    not write and cannot see, and the upstream that quietly stops receiving
    traffic is discovered from the other end, in production.

    A boundary check rather than a string prefix: `/delivery` and `/delivery-eu`
    do not overlap, because no path under one is a path under the other, and
    refusing them would stop a file nobody wrote wrong. `/` overlaps everything
    by construction, so it is the single-upstream form and cannot share a file.
    """
    for i, one in enumerate(routes):
        for other in routes[i + 1 :]:
            a, b = one.prefix, other.prefix
            if a == "/" or b == "/" or a == b or _under(a, b) or _under(b, a):
                raise RoutesError(
                    f"{path}: upstreams '{one.name}' and '{other.name}' both "
                    f"claim requests under {a!r} and {b!r}; a request matching "
                    f"two routes has no answer this gateway can give"
                )


def _under(outer: str, inner: str) -> bool:
    """Whether every path under `inner` is also a path under `outer`."""
    return inner.startswith(outer + "/")


def load_routes() -> list[Route]:
    """The upstreams this gateway fronts, from the routes file.

    Raises rather than serving a configuration nobody meant: a gateway with no
    routes forwards nothing while answering `/health`, which is the state the
    required-variable check has always existed to prevent. `main` turns this
    into a non-zero exit.
    """
    path = routes_file()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RoutesError(f"cannot read {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise RoutesError(f"{path} is not valid UTF-8") from exc

    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise RoutesError(f"{path} is not valid YAML: {exc}") from exc

    # Each level is checked rather than assumed: a hand-edited file goes wrong
    # in more shapes than an empty one, and `.get` on a list is a traceback
    # where a sentence would do.
    if not isinstance(data, dict):
        raise RoutesError(f"{path} must hold a mapping, not {type(data).__name__}")
    # Before anything under `mcp` is read: the version describes the shape this
    # loader is about to assume, so a reader must settle it first or it is
    # parsing on a guess.
    _check_schema_version(path, data.get("schema_version"))
    mcp = data.get("mcp") or {}
    if not isinstance(mcp, dict):
        raise RoutesError(f"{path}: `mcp` must be a mapping, not {type(mcp).__name__}")
    entries = mcp.get("servers") or []
    if not isinstance(entries, list):
        raise RoutesError(
            f"{path}: `mcp.servers` must be a list, not {type(entries).__name__}"
        )

    routes: list[Route] = []
    seen: set[str] = set()
    for entry in entries:
        if not (isinstance(entry, dict) and entry.get("name") and entry.get("url")):
            # Announced rather than dropped quietly: `urls:` for `url:` is a
            # typo that otherwise removes an upstream with no record at any log
            # level, and every other rejection in this file says so.
            log.warning("%s: ignoring an entry without both a name and a url", path)
            continue
        name = str(entry["name"])
        if name in seen:
            raise RoutesError(f"{path}: two upstreams are both named '{name}'")
        seen.add(name)
        extra = set(entry) - ENTRY_KEYS
        if extra:
            log.warning(
                "%s: upstream '%s' sets %s, which this gateway does not read "
                "— only `name`, `url` and `prefix`",
                path,
                name,
                ", ".join(f"`{key}`" for key in sorted(extra)),
            )
        routes.append(
            Route(
                name=name,
                url=str(entry["url"]),
                prefix=_prefix(path, name, entry.get("prefix")),
            )
        )

    if not routes:
        raise RoutesError(f"{path} names no upstream this gateway could front")
    _refuse_overlaps(path, routes)
    return routes
