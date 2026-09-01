"""The two things the conformance vectors cannot say.

The vectors are JSON, so a case's `header` is a JSON value: a string, a list of
strings, or a scalar standing in for something that is not a header at all. Two
of this reader's documented behaviours fall outside that, and both were
unexercised until this file existed — one of them the wall clock, which is the
default every real caller takes.
"""

import time

from gateway.ticket import parse_rail_header

VALID = "eyJhZ2VudF9pZCI6ImEiLCJleHAiOjE3MDAwMDM2MDB9"
"""`{"agent_id":"a","exp":1700003600}` — expires 2023-11-14T23:53:20Z."""

EXP = 1700003600


def _ticket(exp: int) -> str:
    import base64
    import json

    payload = json.dumps({"agent_id": "a", "exp": exp}, separators=(",", ":"))
    return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")


def test_now_defaults_to_the_wall_clock() -> None:
    """Omitting ``now`` reads the clock, rather than standing still at zero.

    Every vector passes a fixed ``now``, so nothing there distinguishes reading
    the clock from any constant. A ticket minted an hour out and one that
    expired an hour ago separate them.
    """
    live = time.time()
    assert parse_rail_header(_ticket(int(live) + 3600)).state == "valid"
    assert parse_rail_header(_ticket(int(live) - 3600)).state == "expired"


def test_now_is_read_afresh_on_each_call() -> None:
    """A ticket expiring between two calls reports differently across them."""
    exp = int(time.time()) + 1
    assert parse_rail_header(_ticket(exp)).state == "valid"
    time.sleep(1.1)
    assert parse_rail_header(_ticket(exp)).state == "expired"


def test_a_tuple_of_header_values_reads_like_a_list() -> None:
    """The signature admits both, and a JSON vector can only spell one.

    Starlette hands over a list, but the type this function documents is either,
    and a caller building one from `scope["headers"]` is as likely to produce a
    tuple.
    """
    assert parse_rail_header((VALID,), EXP - 1).state == "valid"
    assert parse_rail_header(()).state == "absent"
    assert parse_rail_header((VALID, VALID), EXP - 1).state == "undecodable"
