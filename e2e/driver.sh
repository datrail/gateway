#!/bin/sh
# Drives each gateway and asserts what crossed the wire. The assertions are
# WireMock's request journals — the upstream's for what was forwarded, Rail
# Center's for what was reported — not log scraping: a log line says the gateway
# believes it did something, a journal says it happened.
set -eu

UPSTREAM=http://upstream:8080
RAIL_CENTER=http://rail-center:8080
ACCEPT='Accept: application/json, text/event-stream'
JSON='Content-Type: application/json'
fails=0

# Every admin call carries -f, and that is load-bearing rather than tidy. The
# journal reset moved between WireMock majors — `POST /__admin/requests/reset`
# is gone in 3.x, `DELETE /__admin/requests` replaced it — and without -f a 404
# there is silent. A reset that quietly did nothing leaves the previous
# gateway's traffic in the journal, so the next assertion counts requests
# another container made and passes for the wrong reason.
#
# The count is read by stripping whitespace first: WireMock pretty-prints
# `"count" : 7`, so a pattern written against `"count":7` never matches.
count() {
  curl -sf --max-time 15 -H "$JSON" -X POST "$1/__admin/requests/count" -d "$2" \
    | tr -d ' \n' | sed -n 's/.*"count":\([0-9]*\).*/\1/p'
}

reset_journals() {
  sweep_unmatched
  curl -sf --max-time 15 -X DELETE "$UPSTREAM/__admin/requests" >/dev/null
  curl -sf --max-time 15 -X DELETE "$RAIL_CENTER/__admin/requests" >/dev/null
}

forwarded_calls() { count "$UPSTREAM" '{"method":"POST","urlPath":"/mcp"}'; }
denials()         { count "$RAIL_CENTER" '{"method":"POST","urlPath":"/v1/denials"}'; }
bundle_fetches()  { count "$RAIL_CENTER" '{"method":"GET","urlPath":"/v1/policy-bundle"}'; }

# **A denial is reported fire-and-forget**, so every assertion about one has to
# wait for it rather than read a count once. The caller is answered the moment
# the verdict is reached and the report goes out behind it — by design, so that
# Rail Center's availability is not a term in how long a refused request takes.
# An e2e that reads the journal immediately after the 403 is racing that, and
# the race is one it usually wins, which is worse than one it usually loses: it
# passes until the day it does not and then reads as a gateway defect.
await_denial() {
  want=$1 policy=$2 tries=0
  while [ "$tries" -lt 40 ]; do
    got=$(denials_naming "$policy")
    [ "${got:-0}" -ge "$want" ] && { echo "$got"; return 0; }
    tries=$((tries + 1)); sleep 0.25
  done
  echo "${got:-0}"
}

# Denials naming one policy. The gateway must report the rule that *matched*,
# and Rail Center records that attribution without re-deriving it — so a report
# naming the wrong rule is wrong with nothing downstream to contradict it. That
# makes "a denial arrived" the weaker assertion and "it named P2" the real one.
denials_naming() {
  count "$RAIL_CENTER" \
    "{\"method\":\"POST\",\"urlPath\":\"/v1/denials\",\"bodyPatterns\":[{\"matchesJsonPath\":\"\$[?(@.policy_id == '$1')]\"}]}"
}

# Requests no stub answered, as 0 or 1 so `expect ... none` reads it. Every
# other assertion counts requests a stub *matched*, and a stub that went missing
# is invisible to all of them. There is no count endpoint for the unmatched
# journal, so the array is read directly: pretty-printed `"requests" : [ ]`
# becomes `"requests":[]` once whitespace is stripped, and anything else is at
# least one request that arrived with nothing to answer it.
unmatched() {
  if curl -sf --max-time 15 "$1/__admin/requests/unmatched" | tr -d ' \n' \
    | grep -qF '"requests":[]'; then echo 0; else echo 1; fi
}

# The unmatched journal is dropped by every reset along with the matched ones,
# so reading it once at the end reports on the last block alone — the one
# stretch of the run where a stub that stopped matching could not have changed
# any other assertion. Every reset sweeps before it drops, and the answer is
# carried in these two, so the assertions at the end cover the whole run.
unmatched_upstream=0
unmatched_rc=0
sweep_unmatched() {
  [ "$(unmatched $UPSTREAM)" = 0 ] || unmatched_upstream=1
  [ "$(unmatched $RAIL_CENTER)" = 0 ] || unmatched_rc=1
}

# The gateway is FastMCP-served and stateful, unlike the proxy: `initialize`
# returns an `Mcp-Session-Id` and every later call must carry it, or the MCP
# layer answers `400 Missing session ID`. So the handshake is three steps and
# the session id has to be read off the response headers rather than ignored.
#
# Responses are SSE-framed — `event: message` then `data: {…}` — so a body is
# matched on the JSON inside the data line rather than parsed as JSON.
open_session() {
  host=$1; shift
  headers=$(curl -sf --max-time 15 -D - -o /dev/null -X POST "http://$host:8080/mcp" \
    -H "$ACCEPT" -H "$JSON" "$@" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e-driver","version":"1"}}}')
  # Header names are case-insensitive and the casing has changed between
  # releases, so this matches either.
  sid=$(printf '%s' "$headers" | tr -d '\r' \
    | sed -n 's/^[Mm]cp-[Ss]ession-[Ii]d: *//p' | head -1)
  [ -n "$sid" ] || return 1
  curl -sf --max-time 15 -o /dev/null -X POST "http://$host:8080/mcp" -H "$ACCEPT" -H "$JSON" \
    -H "Mcp-Session-Id: $sid" "$@" \
    -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  printf '%s' "$sid"
}

# The HTTP status of one call, with no session — enough for every refusal, since
# a refusal is answered above the MCP layer and never reaches it.
status() {
  host=$1 tool=$2; shift 2
  curl -s --max-time 15 -o /dev/null -w '%{http_code}' -X POST "http://$host:8080/mcp" \
    -H "$ACCEPT" -H "$JSON" "$@" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"$tool\",\"arguments\":{}}}"
}

# `initialize` names no tool, so it is the keyless case: judged by every rule
# that can ask about a message with no endpoint, and by no others.
handshake_status() {
  host=$1; shift
  curl -s --max-time 15 -o /dev/null -w '%{http_code}' -X POST "http://$host:8080/mcp" \
    -H "$ACCEPT" -H "$JSON" "$@" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e-driver","version":"1"}}}'
}

expect() {
  what=$1 want=$2 got=$3
  if [ "${got:-x}" = "$want" ]; then
    printf '  ok    %s\n' "$what"
  else
    printf '  FAIL  %s — wanted %s, got %s\n' "$what" "$want" "${got:-<empty>}"
    fails=$((fails + 1))
  fi
}

# Run first, and before anything resets a journal — which is the whole point.
# A bundle is fetched at startup and on a refresh interval, never per request,
# because the holder serves a cached copy so that evaluating a call never waits
# on the control plane. So *after* a reset nothing fetches, and "no bundle was
# fetched" passes for the pass-through whether or not it ever asked. Counting
# the startup fetches instead is the assertion that can fail: three gateways
# start against the same control plane and exactly two of them ask, so a
# pass-through that quietly fetched would read as 3 here.
printf '\n== a bundle is fetched at startup, by the two gateways that evaluate ==\n'
tries=0
while [ "$(bundle_fetches)" -lt 2 ] && [ "$tries" -lt 40 ]; do
  tries=$((tries + 1)); sleep 0.25
done
sleep 2  # long enough for a third fetch to have shown up if one were coming
expect "exactly two gateways fetched a bundle" 2 "$(bundle_fetches)"

printf '\n== enforce: a caller with no ticket is stopped at the handshake ==\n'
reset_journals
expect "initialize is refused 403" 403 "$(handshake_status gateway-enforce)"
expect "nothing reached the upstream" 0 "$(forwarded_calls)"
expect "it named P0, the rule that matched" 1 \
  "$(await_denial 1 11111111-0000-4000-8000-000000000000)"
# The total, after the scoped wait above has already established that a report
# arrived. It is the assertion that catches a refusal reporting a *second*
# denial naming some other rule — which every policy-scoped count reads as 1
# and passes.
sleep 2  # long enough for a second report to have shown up if one were coming
expect "exactly one denial was reported" 1 "$(denials)"

printf '\n== enforce: a low-posture ticket is stopped at the handshake too ==\n'
reset_journals
expect "initialize is refused 403" 403 \
  "$(handshake_status gateway-enforce -H "x-rail: $LOW_SCORE_TICKET")"
expect "it named P1, not P0" 1 \
  "$(await_denial 1 11111111-0000-4000-8000-000000000001)"

printf '\n== enforce: a good ticket opens a session and its call is forwarded ==\n'
reset_journals
sid=$(open_session gateway-enforce -H "x-rail: $GOOD_TICKET") \
  || { printf '  FAIL  the handshake did not return a session id\n'; fails=$((fails + 1)); sid=none; }
body=$(curl -sf --max-time 15 -X POST "http://gateway-enforce:8080/mcp" -H "$ACCEPT" -H "$JSON" \
  -H "Mcp-Session-Id: $sid" -H "x-rail: $GOOD_TICKET" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"track_package","arguments":{"tracking_number":"pkg-1"}}}' || true)
case "$body" in
  *'"text":"delivered"'*) printf '  ok    the tool call returns the upstream answer\n' ;;
  *) printf '  FAIL  the tool call returns the upstream answer — got %s\n' "$body"
     fails=$((fails + 1)) ;;
esac
sleep 2  # long enough for a report to have arrived if one were sent
expect "no denial was reported" 0 "$(denials)"

printf '\n== enforce: an endpoint rule denies the call and not the handshake ==\n'
# P2 keys on `endpoint_key` and P3 on `skill_match`, so both are dropped from a
# keyless message's chain. That is the whole assertion: the same ticket that
# opened a session above opens one here, and only the call it names is refused.
#
# P3 is what makes "the handshake still succeeds" able to fail. `endpoint_key`
# admits no operator that holds against an absence, so dropping P2 changes
# nothing observable — but `skill_match missing` *holds* on a keyless message,
# so a chain that kept P3 would refuse `initialize` for an agent whose declared
# skills are exactly right. With the key present P3 is reached only for a key
# the ticket declares no skill for: the good ticket declares
# `delivery.track_package`, so `skill_match` resolves present and P3 does not
# hold, and `delivery.forbidden_tool` is refused by P2 first, on priority. The
# block below is where P3 answers for a key that is present.
reset_journals
sid=$(open_session gateway-enforce -H "x-rail: $GOOD_TICKET") || sid=none
expect "the handshake still succeeds" 1 "$([ "$sid" != none ] && echo 1 || echo 0)"
expect "the forbidden call is refused 403" 403 \
  "$(status gateway-enforce forbidden_tool -H "Mcp-Session-Id: $sid" -H "x-rail: $GOOD_TICKET")"
expect "it named P2, the endpoint rule" 1 \
  "$(await_denial 1 11111111-0000-4000-8000-000000000002)"
# The two assertions below are what stop the argument above resting on P3's
# identity. A P3 retargeted to `endpoint_key eq delivery.undeclared_tool` keeps
# its id, its priority and its action, still refuses the call the next block
# makes — and, being endpoint-derived, is dropped from the handshake's chain
# exactly as P2 is, so "the handshake still succeeds" goes back to being unable
# to fail. Nothing that asks about P3's identity separates those two rules.
#
# What separates them is a request whose key is absent and whose chain is *not*
# narrowed. An `unrecognised` `tools/call` is that request: the tool name below
# carries a control character, so no key is composed — but the message still
# names a tool, so it faces the whole chain rather than the keyless one
# (`endpoint.py`'s `unrecognised`, and `chain_for` in `decide.py`). Every
# operator `endpoint_key` admits declines against that absence, so the only
# rule that can answer here is one that *holds* against it: the property the
# handshake above survives, asserted rather than assumed. It is also the one
# refusal shape nothing else in this run exercises.
expect "a tool name that composes no key is refused 403" 403 \
  "$(status gateway-enforce 'track_package\n' -H "x-rail: $GOOD_TICKET")"
expect "it named P3, which holds against an absent key" 1 \
  "$(await_denial 1 11111111-0000-4000-8000-000000000003)"

printf '\n== enforce: a call the ticket declares no skill for is denied by P3 ==\n'
# The refusal shape P2 hides, and the one place skill mismatch is exercised at
# all: a keyless message drops P3 from the chain, `track_package` is declared
# so P3 does not hold, and `forbidden_tool` matches P2 at the lower priority.
# P3 answers here with the key fully present, which is what separates this
# block from the absent-key assertion above it — that one turns on P3's
# condition holding against an absence, this one on the skills the ticket
# carries. Delete P3, disable it, or downgrade it to `alert`, and both fail.
#
# The upstream knows no `undeclared_tool`, and does not need to: the refusal is
# answered above the MCP layer, so nothing is forwarded and the unmatched
# journal stays empty. What the call names has to be a tool the good ticket's
# `skills` omit and P2 does not claim — which is any tool but those two.
reset_journals
expect "the unskilled call is refused 403" 403 \
  "$(status gateway-enforce undeclared_tool -H "x-rail: $GOOD_TICKET")"
expect "it named P3, the skill rule" 1 \
  "$(await_denial 1 11111111-0000-4000-8000-000000000003)"

printf '\n== observe: the same verdict, acted on in no way ==\n'
reset_journals
expect "initialize is not refused" 200 "$(handshake_status gateway-observe)"
sleep 2  # long enough for a report to have arrived if one were sent
expect "no denial was reported" 0 "$(denials)"
# That observe evaluates at all is established above, where its startup fetch
# is one of the two counted. What is left for this block is the mode's own
# claim: the walk reaches the same verdict and nothing is acted on.

printf '\n== none: a pass-through that asks the control plane nothing ==\n'
reset_journals
expect "initialize is not refused" 200 "$(handshake_status gateway-passthrough)"
# Likewise: that the pass-through fetched nothing is the startup count above,
# which is the only place it can be asserted rather than assumed.
sleep 2  # long enough for a report to have arrived if one were sent
expect "no denial was reported" 0 "$(denials)"

printf '\n== every request found a stub ==\n'
sweep_unmatched
expect "no unmatched request reached the upstream" 0 "$unmatched_upstream"
expect "no unmatched request reached rail-center" 0 "$unmatched_rc"

printf '\n'
if [ "$fails" -eq 0 ]; then
  printf 'e2e: all assertions passed\n'
  exit 0
fi
printf 'e2e: %s assertion(s) failed\n' "$fails"
exit 1
