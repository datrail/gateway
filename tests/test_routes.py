"""Reading the routes file, and refusing the ones a gateway must not come up on.

This is startup configuration, so almost every case here is about a **refusal**:
the file is hand-written, it is the only thing that says what this gateway
fronts, and the failures it can carry are silent ones. A gateway that starts
fronting nothing answers `/health` while forwarding nothing; a gateway whose two
prefixes both claim one request answers it from whichever route sorted first.
Neither reports anything, which is why the loader stops the process instead.

The normalisations are asserted too. `/delivery/` and `/delivery` are one route
rather than two that overlap, and `delivery` is the same intent as `/delivery` —
so each of those is a case, because dropping the normalisation turns a file an
operator wrote reasonably into either a refusal or a second route.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from gateway.routes import CONFIG_SCHEMA_MAJOR, RoutesError, load_routes


@pytest.fixture
def routes_file(tmp_path, monkeypatch):
    """Write a routes file and point the loader at it."""

    def write(text: str) -> Path:
        path = tmp_path / "routes.yaml"
        path.write_text(text, encoding="utf-8")
        monkeypatch.setenv("RAIL_GATEWAY_ROUTES_FILE", str(path))
        return path

    return write


def one(name: str, prefix: str | None = None, url: str = "http://u:9000/mcp") -> str:
    entry = f"    - name: {name}\n      url: {url}\n"
    if prefix is not None:
        entry += f"      prefix: {prefix}\n"
    return entry


def file_of(*entries: str, version: str | None = "1.0") -> str:
    head = f'schema_version: "{version}"\n' if version is not None else ""
    return head + "mcp:\n  servers:\n" + "".join(entries)


# --- what a well-formed file yields ----------------------------------------


def test_two_upstreams_are_read_in_the_order_the_file_lists_them(routes_file):
    routes_file(file_of(one("delivery", "/delivery"), one("finretail", "/finretail")))

    routes = load_routes()

    assert [(r.name, r.prefix) for r in routes] == [
        ("delivery", "/delivery"),
        ("finretail", "/finretail"),
    ]


def test_an_absent_prefix_is_the_root(routes_file):
    """The single-upstream deployment: the gateway listens at its root and
    strips nothing, which is the shape every gateway had before this file."""
    routes_file(file_of(one("delivery")))

    (route,) = load_routes()

    assert route.prefix == "/"
    assert route.strips == ""


# --- the normalisations, each of which prevents a different wrong file ------


def test_a_trailing_slash_is_removed(routes_file):
    """`/delivery/` and `/delivery` are one route, not two that overlap.

    Without this the pair below is refused at startup as an overlap, so an
    operator who wrote a trailing slash on one of two entries gets a gateway
    that will not come up.
    """
    routes_file(file_of(one("delivery", "/delivery/"), one("finretail", "/finretail")))

    routes = load_routes()

    assert [r.prefix for r in routes] == ["/delivery", "/finretail"]


def test_a_missing_leading_slash_is_supplied(routes_file):
    """`delivery` is unambiguous about what it meant, and a prefix without a
    leading slash matches no path this gateway ever sees — a route that is
    mounted and silently serves nothing."""
    routes_file(file_of(one("delivery", "delivery"), one("finretail", "/finretail")))

    routes = load_routes()

    assert [r.prefix for r in routes] == ["/delivery", "/finretail"]


@pytest.mark.parametrize("prefix", ['"/a//b"', '"/a/./b"', '"/a/../b"', '"//"'])
def test_a_prefix_no_path_could_match_is_refused(routes_file, prefix):
    """Refused rather than normalised: there is no single thing `/a/../b` could
    have meant, and a prefix this gateway would never match is a route that
    silently serves nothing."""
    routes_file(file_of(one("delivery", prefix)))

    with pytest.raises(RoutesError, match="unusable prefix"):
        load_routes()


# --- the refusals a gateway must not come up past --------------------------


def test_overlapping_prefixes_are_refused(routes_file):
    """`/delivery` and `/delivery/mcp` both claim `/delivery/mcp/...`.

    Resolving by longest-match is a rule the operator did not write and cannot
    see, and the upstream that quietly stops receiving traffic is discovered
    from the other end, in production.
    """
    routes_file(file_of(one("a", "/delivery"), one("b", "/delivery/mcp")))

    with pytest.raises(RoutesError, match="both claim requests under"):
        load_routes()


def test_the_root_prefix_cannot_share_a_file(routes_file):
    """`/` claims everything, so it is the single-upstream form by construction.

    This is the pairing a reader reaches for first — one entry left at the
    default beside one with a prefix — and it is exactly the one that cannot
    work.
    """
    routes_file(file_of(one("delivery"), one("finretail", "/finretail")))

    with pytest.raises(RoutesError, match="both claim requests under"):
        load_routes()


def test_a_sibling_prefix_is_not_an_overlap(routes_file):
    """`/delivery` and `/delivery-eu` share a string prefix and no path.

    The boundary is what this asserts: a loader comparing bare strings refuses a
    file nobody wrote wrong, and the pair is the one `_under`'s docstring exists
    to explain.
    """
    routes_file(file_of(one("delivery", "/delivery"), one("eu", "/delivery-eu")))

    assert [r.prefix for r in load_routes()] == ["/delivery", "/delivery-eu"]


def test_two_upstreams_with_one_name_are_refused(routes_file):
    """A name reaches the log lines about a route, so two of them make every
    line about either one ambiguous."""
    routes_file(file_of(one("delivery", "/a"), one("delivery", "/b")))

    with pytest.raises(RoutesError, match="two upstreams are both named"):
        load_routes()


def test_a_file_naming_no_upstream_is_refused(routes_file):
    """A gateway fronting nothing forwards nothing and answers `/health` while
    doing it — the state the required-variable check has always prevented."""
    routes_file('schema_version: "1.0"\nmcp:\n  servers: []\n')

    with pytest.raises(RoutesError, match="names no upstream"):
        load_routes()


def test_a_file_whose_entries_are_all_unusable_is_refused(routes_file, caplog):
    """An entry missing `url` is warned about and skipped; a file of nothing but
    those still names no upstream, and must not start a gateway."""
    routes_file('schema_version: "1.0"\nmcp:\n  servers:\n    - name: delivery\n')

    with (
        caplog.at_level(logging.WARNING, logger="gateway"),
        pytest.raises(RoutesError, match="names no upstream"),
    ):
        load_routes()

    assert "ignoring an entry without both a name and a url" in caplog.text


# --- the version gate ------------------------------------------------------


def test_a_later_major_version_is_refused(routes_file):
    """The version describes the shape this loader is about to assume, so a
    file it cannot read whole must stop it rather than be parsed on a guess."""
    routes_file(file_of(one("delivery", "/delivery"), version="2.0"))

    with pytest.raises(RoutesError, match="a format this gateway does not read"):
        load_routes()


def test_an_absent_version_is_read_as_the_supported_major_and_warned_about(
    routes_file, caplog
):
    """Every file written before the field existed omits it, and stopping those
    costs an operator a restart for nothing. The warning is what gets the line
    added before the format moves."""
    routes_file(file_of(one("delivery", "/delivery"), version=None))

    with caplog.at_level(logging.WARNING, logger="gateway"):
        routes = load_routes()

    assert [r.name for r in routes] == ["delivery"]
    assert f"reading it as {CONFIG_SCHEMA_MAJOR}.0" in caplog.text


def test_a_schema_version_that_is_not_a_version_is_refused(routes_file):
    """`1.x` has a major this gateway reads and is still not a version: honouring
    it means honouring a file whose version nobody can compare to the next."""
    routes_file(file_of(one("delivery", "/delivery"), version="1.x"))

    with pytest.raises(RoutesError, match="is not a version"):
        load_routes()


# --- an entry carrying something this gateway does not read ----------------


def test_an_unread_entry_key_is_said_out_loud(routes_file, caplog):
    """`headers:` is how every mainstream MCP client config spells an upstream
    credential, so an operator will write it — and a gateway that dropped it
    silently would 401 every call to that upstream with nothing saying why."""
    entry = one("delivery", "/delivery") + "      headers: {a: b}\n"
    routes_file(file_of(entry))

    with caplog.at_level(logging.WARNING, logger="gateway"):
        load_routes()

    assert "`headers`" in caplog.text


# --- the file itself -------------------------------------------------------


def test_an_absent_file_is_refused_by_name(routes_file, tmp_path, monkeypatch):
    """The image bakes a path that holds no file, so a container started without
    one mounted stops here rather than coming up fronting nothing."""
    monkeypatch.setenv("RAIL_GATEWAY_ROUTES_FILE", str(tmp_path / "absent.yaml"))

    with pytest.raises(RoutesError, match="cannot read"):
        load_routes()


def test_a_file_that_is_not_a_mapping_is_refused(routes_file):
    routes_file("- delivery\n")

    with pytest.raises(RoutesError, match="must hold a mapping"):
        load_routes()
