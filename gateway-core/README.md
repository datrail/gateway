# gateway-core

`gateway.core`, DatRail Gateway's vendor-neutral enforcement core: `x-rail`
ticket parsing, endpoint resolution, policy bundle ingestion and decisions. It
imports no other member of this workspace; every interface builds on it. See
the [main README](../README.md) for the whole.

What every interface takes from it, so they behave alike:
- **the settings** they all read, and their refusals (`settings`, `mode`);
- **logging**, its format and level (`logs`);
- **the lifecycle**: the first fetch's 5 s grace, the refresh loop, and
  readiness (`lifecycle`);
- **enforcement**: judging one call, the refusal bodies, and denial
  reporting (`enforcement`);
- **the enforcement contract**, `ENFORCEMENT_CASES` in
  [`tests/core_support.py`](tests/core_support.py), which every interface's
  tests run.

An interface adds only its host: how a request arrives, and how the verdict
is applied.

## The policy bundle

**How much of a decision is acted on is the bundle's to say, not the
deployment's** — the bundle carries an `enforcement` posture, so moving a
gateway between judging nothing, reporting and refusing is a poll rather than a
redeploy. Decisions use the last valid policy bundle, so a failed refresh does
not silently become an empty policy. [`schemas/`](../schemas/) defines the
ticket, bundle and denial-event wire shapes.

## Endpoint keys, and the constraint they place on you

Rail Center composes `<slug>#<path>#<method>#<call>` and publishes that whole
key. This gateway holds no data source slug — it fronts several data sources and
a data source may sit behind several gateways, so nothing local can name that
relationship — so it composes `<path>#<method>#<call>` from the request and
strips the first segment off each of the bundle's keys to meet it.

`<path>` is the path **the upstream serves**, not the one the caller dialled:
the route prefix is removed first. That is what keeps one endpoint to one key,
since the same MCP server behind two gateways at different prefixes would
otherwise produce two keys for one row.

**Only a `tools/call` composes a key.** An endpoint is a tool, so every other
method carries none, is matched against no binding, and is never reached by the
fallback.

**This implementation requires endpoint keys to be unique within one gateway
once the slug is stripped.** The contract is the whole key — Rail Center
publishes `<slug>#<path>#<method>#<call>` and it identifies one endpoint
unambiguously — but this gateway composes no slug, so it can only match on the
last three parts. Two data sources behind one gateway, both serving `/mcp`, both
with a `search` tool, therefore reach it as one key. A gateway that resolved the
data source from the route a call arrived on would match on the whole key and
carry no such constraint; nothing in the contract prevents that, and this is
where the limitation would be lifted. Rail Center does not enforce it and is not
asked to.

**What the gateway refuses is a bundle that binds both of them.** Two bindings
whose keys are one key once the slug is stripped are refused together, naming
both full keys, because serving either would be the gateway choosing on your
behalf. A refused bundle leaves the one already held in place — the gateway goes
on enforcing the last ruleset it understood — and only a first fetch leaves it
holding nothing, where `/ready` answers 503. A binding whose key cannot be read
at all is logged and skipped instead: it narrows one endpoint and says nothing
about the others.

**A bundle that binds only one of them is served, and it covers both.** The
refusal compares bindings against each other, so it cannot see a collision only
one side of which is bound: a binding published for one data source narrows the
identically-named tool on every other upstream behind the same gateway, with no
refusal and no log line, and an `open` binding on one therefore opens the other.
Nothing in a routes file or a key names a data source, so the gateway has no way
to tell the two apart — **keep the constraint above whether or not you bind both
sides.**

**And a denial names the binding's data source, not the caller's.** The same
limitation seen from the report rather than from the verdict: a refusal on a
shared key is reported under the slug of whichever binding matched, so a call to
one upstream can be recorded against another. The gateway matched on a key with
no data source in it and has nothing better to send — reporting the slug-less
form instead would lose an attribution that is correct in every other case.

## Configuration

Every interface reads these, and refuses the same mistakes. Each interface's
README lists its own variables beside them, and
[`.env.example`](../.env.example) lists them all. A refusal stops the process
at startup: it logs one line naming the variable, with no traceback, and exits
2. An interface's own settings, and standalone's routes file, are refused the
same way.

#### `RAIL_PLUGIN_ENABLED`

Whether RailXia is installed on this deployment: `true` or `false`, case
folded. Blank or unset is `false`, so a plain gateway needs no variable at
all. Off, it fetches no bundle and reads no Rail Center variable; on, it polls
Rail Center and takes its posture from the bundle. It does not say how much of
a decision is acted on: that is the bundle's `enforcement` posture.

Off beside Rail Center configuration — `RAIL_CENTER_URL`, `RAIL_AUTH_TOKEN`,
or `RAIL_AUTH_MODE` other than `none` — is refused, naming each one found, so
the default can't silently unenrol a gateway that was enforcing.

#### `RAIL_CENTER_URL`

Where the policy bundle comes from, as an origin (e.g.
`https://rail-center.example.com`). Required when the plugin is on. It must
name a host. A `user:password@` in it is sent as Basic authentication, and is
refused beside `RAIL_AUTH_MODE=bearer`. Error messages never carry it.

#### `RAIL_GATEWAY_SLUG`

Which gateway this is, and so whose bundle it fetches. Required when the
plugin is on. It is **not** a data source's slug: a gateway fronts several data
sources, and a data source may sit behind several gateways.

#### `RAIL_AUTH_MODE`

How to authenticate to Rail Center: `none` or `bearer`. Defaults to `none`.
`gcp` is refused as not implemented by this component.

#### `RAIL_AUTH_TOKEN`

The bearer token. Required under `RAIL_AUTH_MODE=bearer`, and refused under
`none`. It must be printable ASCII; the refusal names the offset, never the
token.

#### `RAIL_GATEWAY_BUNDLE_REFRESH_SECONDS`

How often to fetch the bundle again, in seconds. Defaults to `60`. Not an
integer is refused; below `5` is raised to `5` with a warning.

#### `RAIL_GATEWAY_PORT`

The port to listen on. Defaults to `8080`; blank is the default. Not an
integer, or outside 1–65535, is refused.

#### `RAIL_GATEWAY_LOG_LEVEL`

`CRITICAL`, `ERROR`, `WARNING`, `INFO` or `DEBUG`, case folded. Defaults to
`INFO`; blank is the default. Anything else is refused.

#### `RAIL_TICKET_MODE`

Retired: the posture now arrives in the bundle. Any value but blank is
refused, naming `RAIL_PLUGIN_ENABLED` and the bundle.

## Tests

`tests/vectors/` holds the conformance vectors: ticket reading, bundle
validation and the evaluation walk, written as data so a reimplementation in
another language is answerable to the same cases.

`tests/core_support.py` holds `ENFORCEMENT_CASES`, the enforcement contract
every interface runs: a held bundle and one request per row, and the answer and
denial report they must give. `make dump-enforcement-cases` writes the table to
`enforcement-cases.json` for review.
