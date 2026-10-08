# The end-to-end stacks

One stack per interface: its image against a stubbed Rail Center and a stubbed
MCP upstream, with a driver that asserts what crossed the wire. It needs neither
a Rail Center nor an agent, so it is also the quickstart.

```bash
make e2e              # every stack in turn
make e2e-standalone   # one stack
make e2e-down         # remove every stack's containers and volumes
```

The result is the `driver` container's exit code. A stack's target leaves its
containers up so a failed run's logs can be read; `make e2e-down` removes them.

```
e2e/
  shared/       the stubs, the base services, the driver's helpers
  standalone/   the standalone gateway's stack
  apigee-grpc/  the Apigee callout's stack, behind a stand-in for Apigee
    live/       a paid session on real Apigee X, run by hand
```

`apigee-grpc/live/` runs the callout's driver against real Apigee X on GCP,
never in CI: see [its README](apigee-grpc/live/README.md).

## What it proves that the unit suite cannot

- the **image** runs: entrypoint, non-root user, mounted routes file, the
  configured port;
- a **real socket**, DNS name and TCP connection;
- a **policy fetched** from a control plane, and a **denial reaching it**;
- a **stateful MCP handshake** through the gateway;
- the postures side by side, served from **one control plane**.

## Shared

The stubs are WireMock (`services.yml`), and the assertions read their request
journals, not logs: a log says the gateway believes it did something, a journal
says it happened.

- `rc-mappings/` serves the policy bundle and accepts denials. Each bundle
  matches one credential's `Authorization`; the table below gives its posture.
- `mcp-mappings/` answers as an MCP server.
- `tickets.env` holds two `x-rail` tickets: unsigned base64url JSON.
- `lib.py` holds the driver's helpers, standard library only.

A stub whose body uses handlebars must declare
`"transformers": ["response-template"]`. Without it WireMock serves the template
literally with a `200`, and the client fails later with a JSON parse error.

## Standalone

| Service | Configuration | Posture |
|---|---|---|
| `gateway-enforce` | enrolled, credential `e2e-enforce` | `enforce`, `fallback: pass` |
| `gateway-observe` | enrolled, credential `e2e-observe` | `observe` |
| `gateway-fallback` | enrolled, credential `e2e-fallback` | `enforce`, `fallback: block`, one binding |
| `gateway-passthrough` | `RAIL_PLUGIN_ENABLED=false`, no control plane | none |
| `gateway-unreachable` | enrolled, Rail Center unreachable, `RAIL_GATEWAY_PORT=9100` | no bundle ever arrives |
| `image-user` | the same image, sleeping | its healthcheck asserts uid 10001 |

`gateway-enforce`, `-observe` and `-fallback` are configured identically: the credential selects
the bundle, as in production, so no deployment variable sets a posture. The
pass-through is not the same as a bundle saying `mode: none`, which still polls.

What the driver asserts:
- exactly three gateways fetch a bundle at startup;
- without a ticket, and with a low-posture one, the handshake passes, the call
  is refused, and the denial names the rule that matched (P0, P1);
- a good ticket's call is forwarded, with no denial;
- an endpoint rule (P2) refuses the call but not the handshake; a tool name that
  composes no key is refused by P3, the rule that holds against an absent key;
- an undeclared skill is refused by P3;
- `observe` and the pass-through refuse and report nothing;
- `fallback: block` forwards the bound call and refuses an unbound one, reporting
  a denial with no `policy_id`;
- a gateway that can't reach Rail Center still starts, serves `/health` on the
  port it was given, and answers `/ready` with `503`;
- every request found a stub.

### Easy to get wrong

**Bundles are fetched at startup, not per request.** So the fetch count is read
before any journal reset, and a stub left over from an earlier run inflates it.
`--force-recreate` prevents that.

**Denials are reported fire-and-forget**, after the caller is answered, so the
driver waits for them. Reading the journal right after the `403` passes most of
the time, then fails as if the gateway were at fault.

## Apigee callout

The callout behind `apigee_standin.py`, a stand-in for an Apigee proxy running
the [reference bundle](../gateway-apigee-grpc/apigee/README.md). **The
stand-in is a model of Apigee, not Apigee:** it does only what the bundle,
Apigee's docs and the [live harness](apigee-grpc/live/README.md)'s runs say
Apigee does. The same Apigee cases run on both; they were written and passed
live first. The driver and the stand-in run in the callout's own image, which
has grpcio and the generated code.

| Service | Configuration |
|---|---|
| `apigee` | the stand-in: `/mcp` through `callout`, `/no-callout` through a callout host that never resolves, to `upstream` |
| `callout` | enrolled, credential `e2e-enforce` |
| `callout-unreachable` | enrolled, Rail Center unreachable, `RAIL_GATEWAY_PORT=9100` |

What the stand-in models, each checked on the live harness (2026-10-08) unless
noted:
- header values split on commas, and a repeated line adding items, in what the
  callout sees; headers it doesn't return forwarded as received;
- a header returned with an empty list removed (Apigee's docs); one returned
  with items written back as a line of its own each;
- the answer's content forwarded as the body, even empty;
- `RF-Refuse` answering `rail.status` with `rail.body`;
- any callout failure answering `RF-CalloutFailed`'s 503, read from the bundle:
  unreachable, timed out, a gRPC error, or an answer over gRPC's 4 MiB;
- `uri` with the query string; a body that isn't UTF-8 sent with replacement
  characters.

Not modelled, so checked live only: TLS and the load balancer, Cloud Run's IAM
check on the callout, base and target path rewriting beyond one prefix,
Apigee's payload limit and target timeout, streamed responses, a 405 without
`Allow` (a 502 on Apigee), analytics.

What the driver asserts:
- the image runs as uid 10001; `callout` fetches a bundle and its gRPC
  liveness and readiness are `SERVING`; a direct `ProcessMessage` judges a
  call; `callout-unreachable` is live on port 9100 and not ready;
- then the Apigee cases, listed in the [live README](apigee-grpc/live/README.md#what-the-driver-checks);
- every request found a stub.
