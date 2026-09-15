# The e2e stack

```bash
docker compose -f e2e/compose.yml up --build --force-recreate --abort-on-container-exit --exit-code-from driver
docker compose -f e2e/compose.yml down -v --remove-orphans
```

The exit code of the first is the result. It is both the test and the quickstart: the only path where someone with neither a Rail Center nor an agent sees a policy fetched, a call refused and a denial reported.

Four gateways run against one stubbed control plane and one stubbed MCP server. The stubs are WireMock, and **the assertions are its request journals rather than the gateway's log output** — a log line says the gateway believes it did something, a journal says it happened.

**Three of the four are configured identically**, and that is an assertion rather than a tidy-up. A posture is no longer a deployment's to declare: `RAIL_TICKET_MODE` says only whether a control plane exists, and `enforce`, `observe` and the two fallbacks arrive in the bundle. What selects which bundle a gateway is served is the credential it presents — which is how Rail Center resolves a gateway in production — so the stub matches on `Authorization` and serves three postures from one route. The fourth gateway sets `RAIL_TICKET_MODE=none` and is a deployment with no control plane at all, which is not the same state as a bundle saying `mode: none`: that one still polls, and can be told something else.

## What each block establishes

| | why it is here |
|---|---|
| exactly three gateways fetch a bundle at startup | The only place a pass-through's silence can be *counted* rather than assumed. See below. |
| no ticket → session opens, first call refused, denial names P0 | The whole path, end to end: the session messages forwarded unjudged, the call evaluated, refused above the MCP layer, reported. |
| low posture → session opens, call refused, denial names **P1** | The denial names the rule that *matched*, not the first in the chain. Nothing downstream re-derives this, so a wrong id would be wrong forever. |
| good ticket → session opens, call forwarded, no denial | The transparent case. A gateway that refuses everything would pass every assertion above it. |
| good ticket → handshake succeeds, `forbidden_tool` refused, denial names P2 | **The keyless narrowing, over the wire.** P2 keys on `endpoint_key` and P3 on `skill_match`, so both are dropped from `initialize`'s chain and both apply to the call. P3 is the one that makes the drop observable — `skill_match missing` *holds* against an absent key, so a chain that kept it would refuse the handshake, while `endpoint_key` admits no operator that holds either way. One ticket, two outcomes, decided by what the message names. |
| good ticket → a tool name that composes no key is refused, denial names **P3** | What makes the row above able to fail. That row rests on P3 being a rule whose condition *holds against an absent key*, and its own assertions pin only P3's id: a P3 retargeted to an `endpoint_key` rule keeps that id, denies the same calls, and is dropped from `initialize`'s chain exactly as P2 is — leaving the narrowing unobservable again. An `unrecognised` `tools/call` — here a tool name carrying a control character — is the one request whose key is absent and whose chain is *not* narrowed, so only a rule that holds against an absence can refuse it. |
| good ticket → a tool it declares no skill for is refused, denial names **P3** | Skill mismatch, the third refusal shape, and the only place the ticket's `skills` decide anything — `forbidden_tool` matches P2 at the lower priority, and `track_package` is declared. It pins P3's presence and its `block` action for a key that is fully present; the row above pins the condition P3 is written against. |
| `enforce` + `fallback: block` → the bound endpoint is forwarded, an unbound one is refused, and **no denial is reported** | The other half of `enforcement`, and the only place a caller's answer turns on something other than a policy. Both calls carry the same good ticket, and the two status codes are not what establishes it: `gateway-enforce`, whose bundle differs only in its fallback, answers the same pair identically — it refuses the unbound call by P3, the skill rule, rather than by a fallback. What separates the fallback from the chain is the third assertion, that nothing is reported: a report names the policy that matched and none did, and `policy_id` has no absent form. |
| `observe` → not refused, nothing reported | The same walk and the same verdict in the log, acted on in no way. |
| `none` → not refused, nothing reported | A pass-through that asks the control plane nothing. |
| no unmatched request at either stub | A stub that silently stopped matching is invisible to every count above, which only ever counts requests a stub *answered*. |

## Two things that are easy to get wrong here

**A bundle fetch is a startup and refresh event, never a per-request one.** The holder serves a cached copy so that evaluating a call never waits on the control plane. So after a journal reset nothing fetches, and "no bundle was fetched" passes for the pass-through whether or not it ever asked — an assertion that cannot fail. Counting the startup fetches before any reset is what replaces it: four gateways start and exactly three of them ask. Three rather than two is the RC-312 rule and not an arithmetic detail — a gateway *polls* because it is enrolled, not because of its posture, so one told `mode: none` in its bundle would still be among the three. A gateway that stopped polling at `none` could never be told it had been moved off it. The refresh interval is pinned to an hour in `compose.yml` so a refresh landing mid-count cannot turn that into a race. **It is also the one assertion no reset may precede, so it cannot defend itself against a journal that outlived the run before it**: a stub container left behind by an aborted run, or by `up -d`, carries its fetches forward and the count reads 6 rather than 3 — naming a gateway for a stub's state. `--force-recreate` on the way in is what closes that, and the `down` on the way out is what keeps a failed run from leaving one behind; CI runs the same `down` in an `if: always()` step.

**A denial is reported fire-and-forget**, so every assertion about one waits for it rather than reading a count once. The caller is answered the moment the verdict is reached and the report goes out behind it, by design, so that Rail Center's availability is not a term in how long a refused request takes. An e2e that reads the journal immediately after the `403` is racing that — and it is a race it usually *wins*, which is worse than one it usually loses: it passes until the day it does not, and then reads as a gateway defect.

## The stubs

`mcp-mappings/` answers as an MCP server; `rc-mappings/` serves the policy bundle and accepts denials. Both are static JSON, with one trap worth naming: **a stub whose body contains handlebars must declare `"transformers": ["response-template"]`**, or WireMock serves the `{{jsonPath …}}` literally. That failure does not look like a templating failure — the body is served with a `200`, and the client reports a JSON parse error somewhere else entirely.

The three bundle mappings differ only in the `Authorization` they match and the `enforcement` they carry; a request presenting any other credential matches none of them, which the final unmatched-journal sweep catches. The `e2e-*` credentials are stub values a WireMock matches on and authenticates nothing with.

`tickets.env` holds two pre-minted `x-rail` tickets. They are base64url JSON and **not signed** — the ticket contract has no signature, which is why the gateway treats everything in one as a claim.

## The three services that are not gateways

`rail-center` and `upstream` are the stubs. `image-user` is the same image the four gateways run, doing nothing, whose healthcheck asserts the container's uid — that cannot be an assertion in `driver.sh`, since a uid is not visible across containers and reporting it from `/health` would be a production change made for a test. A wrong uid never reports healthy, the run stops at "dependency failed to start", and the driver never executes.
