# Changelog

Notable changes to this project. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Released versions correspond to published images at `ghcr.io/datrail/gateway`.

## [Unreleased]

### Changed

- Session and discovery messages — `initialize`, `ping`, `notifications/*`, `tools/list`, `prompts/list`, `resources/list`, `resources/templates/list` — are forwarded without a policy walk and reported to nobody. A binding cannot narrow a message that names no endpoint, so judging them let a rule bound to one endpoint close the whole session; enforcement is per `tools/call`. Other keyless methods (`resources/read`, `prompts/get`) are still judged.

### Added

- An enforcement point that fronts an MCP server as a transparent proxy: admitted calls are forwarded and answered as though it were not there.
- `x-rail` ticket reading, classified into one state per outcome — `absent`, `undecodable`, `malformed`, `expired`, `valid`. All four unusable states fold into one decision, and they stay distinguishable so that an operator can tell a credential that lapsed from one that could never be read.
- Policy bundle validation against `schemas/policy-bundle.schema.json`.
- Conformance vectors in `tests/vectors/`, covering ticket reading, bundle validation and the evaluation walk. They are written as data against Rail Center's policy evaluation contract, so a reimplementation in another language is answerable to the same cases, and several are written deliberately against Rail Center's current behaviour where it departs from that contract.
- A held bundle, refreshed on an interval, so deciding a call never waits on the control plane. **A failed fetch leaves the last good bundle in place** rather than admitting everything — a control plane that is down costs freshness, not enforcement.
- `GET /ready`, reporting readiness distinctly from `GET /health`'s liveness. `/ready` answers `503` until a bundle is held, except under `RAIL_TICKET_MODE=none`, which builds no holder and so is ready at once; a gateway that has never reached its control plane forwards traffic exactly as one that has, because readiness reports rather than gates. It is what distinguishes the three states in which traffic passes unjudged — no control plane, enrolled but holding no bundle yet, and a bundle saying judge nothing.
- Evaluation of every call against the held bundle, implementing Rail Center's policy evaluation contract: ordering then narrowing, `open` allowing at the end of the walk, and any action that is not `alert` denying. A message that names no endpoint — `initialize` — is judged by the rules that can ask about it and by no others.
- `RAIL_TICKET_MODE`, one of `none` or `plugin`, defaulting to `plugin`. It says whether this gateway has a control plane and nothing more: `none` fetches no bundle and reads no control-plane configuration, while `plugin` polls Rail Center and takes its posture from what arrives. The variable is platform-wide — the proxy in front reads the same one — so case is folded and one value configures a zone. `observe` and `enforce` were values of it and are refused at startup, with a message naming where the posture went.
- **The enforcement posture arrives in the policy bundle**, as `enforcement: {mode, fallback}`, and is read per request rather than at start-up. `mode` is `none`, `observe` or `enforce`: all three fetch, and the mode selects only what happens once the bundle is in hand — a gateway that stopped polling at `none` could not be told it had been moved off `none`, so the kill switch would turn one way only. `fallback`, consulted at `enforce` and nowhere else, says what happens to a call no binding matches: `pass` hands it to the whole chain, and `block` refuses it with `403` before the chain is consulted. A `block` refusal is reported to nobody — a denial names the policy that matched, and none did. A bundle carrying no `enforcement` is read as judging nothing, which is the one reading that enforces no decision the control plane never stated.
- Enforcement: a refused call is answered `403` **above the MCP layer**, as an HTTP status rather than a JSON-RPC error inside a `200`. A request the ruleset could not be applied to is answered `503`.
- Denial reporting to Rail Center, naming the policy that actually matched. Fire-and-forget, so that the control plane's availability is not a term in how long a refused request takes. **A refusal is not a denial**: a `503` is reported nowhere, because naming a policy in a report is the only thing that makes it the policy that decided.
- `schemas/x-rail-ticket.schema.json`, `schemas/policy-bundle.schema.json` and `schemas/denial-event.schema.json` — the three wire contracts, each carrying the rules that are about meaning rather than shape.
- `e2e/`: three gateways, one per mode, against a stubbed control plane and a stubbed MCP server, asserting what crossed the wire from WireMock's request journals rather than from log output. Run in CI, since it is the only gate that exercises a decision over the wire.
- `tools/check-publication-defaults.sh`, scanning the tree for local home paths and `.internal` hostnames that must not survive publication.
- Container images with an SBOM. A signed build-provenance attestation is attached where the repository is public — attestation requires that or GitHub Enterprise Cloud — and a release that cannot produce one warns rather than failing.

### Security

- **The `x-rail` ticket is unsigned.** `agent_id` and `posture_score` are chosen by whoever sent the request; they are evaluated and reported as claims, never as established identity.
- A caller's claimed ticket status is recorded under `claimed-x-rail-status`, never under the key an operator reads as the decision.
