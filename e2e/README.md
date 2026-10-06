# The end-to-end stacks

One stack per interface: its image against a stubbed Rail Center and a stubbed
MCP upstream, with a driver that asserts what crossed the wire. Nothing outside
this directory is needed, so it is also the quickstart.

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
```

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

- `rc-mappings/` serves the policy bundle and accepts denials. The three bundles
  differ only in the `Authorization` they match and the `enforcement` they carry.
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
