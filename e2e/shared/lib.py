"""Helpers every e2e driver asserts with. Standard library only.

Assertions read WireMock's request journals, not logs: a log says the gateway
believes it did something, a journal says it happened.
"""

import json
import time
import urllib.error
import urllib.request

UPSTREAM = "http://upstream:8080"
RAIL_CENTER = "http://rail-center:8080"
TIMEOUT_SECONDS = 15
MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "e2e-driver", "version": "1"},
    },
}

fails = 0


def _send(method, url, body=None, headers=None):
    """The response, open. Raises `HTTPError` on anything but a 2xx."""
    request = urllib.request.Request(
        url,
        data=None if body is None else json.dumps(body).encode(),
        method=method,
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    return urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS)


# Raises on failure: a reset that silently 404s (the endpoint moved in WireMock
# 3.x) would leave the last block's traffic in the journal.
def _admin(method, base, path, body=None):
    with _send(method, base + path, body) as response:
        text = response.read().decode()
    return json.loads(text) if text else None


def count(base, pattern):
    """How many requests the stub at `base` answered that match `pattern`, or
    None if it could not be asked."""
    try:
        return _admin("POST", base, "/__admin/requests/count", pattern)["count"]
    except (OSError, ValueError, KeyError):
        return None


# Session messages are forwarded unjudged; a refusal must stop the `tools/call`.
def forwarded_tool_calls():
    return count(
        UPSTREAM,
        {
            "method": "POST",
            "urlPath": "/mcp",
            "bodyPatterns": [{"matchesJsonPath": "$[?(@.method == 'tools/call')]"}],
        },
    )


def denials():
    return count(RAIL_CENTER, {"method": "POST", "urlPath": "/v1/denials"})


def bundle_fetches():
    return count(RAIL_CENTER, {"method": "GET", "urlPath": "/v1/policy-bundle"})


# The rule that matched: Rail Center records it without re-deriving it.
def denials_naming(policy):
    return count(
        RAIL_CENTER,
        {
            "method": "POST",
            "urlPath": "/v1/denials",
            "bodyPatterns": [{"matchesJsonPath": f"$[?(@.policy_id == '{policy}')]"}],
        },
    )


# A fallback refusal omits `policy_id`; this matches its absence, not a null.
def denials_naming_no_policy():
    return count(
        RAIL_CENTER,
        {
            "method": "POST",
            "urlPath": "/v1/denials",
            "bodyPatterns": [{"matchesJsonPath": "$[?(!@.policy_id)]"}],
        },
    )


def wait_for(read, want, tries=40, interval=0.25):
    """Polls `read` until it reaches `want`, or `tries` run out; returns what it
    last read."""
    for _ in range(tries):
        got = read()
        if (got or 0) >= want:
            return got
        time.sleep(interval)
    return got


# Denials are reported fire-and-forget, after the caller is answered, so wait.
def await_denial(want, policy):
    return wait_for(lambda: denials_naming(policy), want) or 0


# 1 if any request found no stub, which no matched-request count would show.
def unmatched(base):
    try:
        requests = _admin("GET", base, "/__admin/requests/unmatched")["requests"]
    except (OSError, ValueError, KeyError):
        return 1
    return 0 if not requests else 1


# Every reset sweeps first, so the final check covers the whole run.
unmatched_upstream = 0
unmatched_rc = 0


def sweep_unmatched():
    global unmatched_upstream, unmatched_rc
    if unmatched(UPSTREAM):
        unmatched_upstream = 1
    if unmatched(RAIL_CENTER):
        unmatched_rc = 1


def reset_journals():
    sweep_unmatched()
    _admin("DELETE", UPSTREAM, "/__admin/requests")
    _admin("DELETE", RAIL_CENTER, "/__admin/requests")


def _post_mcp(url, payload, headers):
    """The status and body of one MCP POST, whatever the status."""
    try:
        with _send("POST", url, payload, {**MCP_HEADERS, **headers}) as response:
            return response.status, response.read().decode(), response.headers
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(), exc.headers


# The gateway is stateful: every call after `initialize` carries its session id.
def open_session(url, headers=None):
    """A session id from a full handshake at `url`, or None if it failed."""
    headers = headers or {}
    try:
        status, _, answer = _post_mcp(url, INITIALIZE, headers)
        sid = answer.get("Mcp-Session-Id") if status == 200 else None
        if not sid:
            return None
        status, _, _ = _post_mcp(
            url,
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"Mcp-Session-Id": sid, **headers},
        )
    except OSError:
        return None
    return sid if 200 <= status < 300 else None


def get_status(url):
    """The HTTP status of a GET, or None if nothing answered."""
    try:
        with _send("GET", url) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except OSError:
        return None


# `initialize` names no endpoint, so it is forwarded without a policy walk.
def handshake_status(url, headers=None):
    try:
        return _post_mcp(url, INITIALIZE, headers or {})[0]
    except OSError:
        return None


def call_tool(url, tool, arguments=None, headers=None, request_id=9):
    """The status and body of a `tools/call`. The body is SSE-framed."""
    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments or {}},
    }
    try:
        status, body, _ = _post_mcp(url, payload, headers or {})
    except OSError:
        return None, ""
    return status, body


# No session needed: refusals are answered above the MCP layer.
def status(url, tool, headers=None):
    return call_tool(url, tool, headers=headers)[0]


def ok(what):
    print(f"  ok    {what}")


def fail(message):
    global fails
    fails += 1
    print(f"  FAIL  {message}")


def expect(what, want, got):
    if got is not None and str(got) == str(want):
        ok(what)
    else:
        fail(f"{what} — wanted {want}, got {'<empty>' if got is None else got}")


def block(title):
    print(f"\n== {title} ==")


def finish():
    """Print the verdict and exit with it."""
    print()
    if fails == 0:
        print("e2e: all assertions passed")
        raise SystemExit(0)
    print(f"e2e: {fails} assertion(s) failed")
    raise SystemExit(1)
