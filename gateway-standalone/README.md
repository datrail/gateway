# gateway-standalone

`gateway.standalone`, the FastMCP/Starlette host that runs
[gateway-core](../gateway-core/README.md) in front of MCP servers: process
configuration, the routes file, and the HTTP server. Its Dockerfile builds
`ghcr.io/datrail/gateway`. See the [main README](../README.md) for the whole.

## Run

To proxy a real MCP server:

```bash
docker run --rm -p 8080:8080 \
  -e RAIL_PLUGIN_ENABLED=true \
  -e RAIL_CENTER_URL=https://rail-center.example.com \
  -e RAIL_GATEWAY_SLUG=edge \
  -v "$PWD/routes.yaml:/etc/rail/routes.yaml:ro" \
  ghcr.io/datrail/gateway:latest
```

See [`.env.example`](../.env.example) for the complete configuration. `/health`
reports liveness, `/ready` reports whether a policy bundle is available, and
`/mcp` is the proxied endpoint.

`RAIL_PLUGIN_ENABLED` says whether RailXia is installed on this deployment at
all: false is a plain gateway that contacts no control plane, true one that
polls Rail Center for its policy bundle by `RAIL_GATEWAY_SLUG` — the gateway's
own identity, and not any data source's. What it does with the bundle is
[gateway-core](../gateway-core/README.md#the-policy-bundle)'s to say.

## What it fronts

One gateway fronts several MCP servers, named in a routes file:

```yaml
schema_version: "1.0"
mcp:
  servers:
    - name: delivery
      url: http://delivery-mcp:9000/mcp
      prefix: /delivery
    - name: finretail
      url: http://finretail-mcp:9001/mcp
      prefix: /finretail
```

`prefix` defaults to `/`, the single-upstream deployment, where the gateway
listens at its root and strips nothing. Every entry in a file naming more than
one upstream carries a prefix of its own: `/` overlaps every other prefix, and
the pair is refused at startup.

`prefix` is where this gateway listens for that upstream, and it is the only
thing that decides routing — an MCP `tools/call` names a tool and nothing else,
so two upstreams reachable at one address are indistinguishable in the message.
**Overlapping prefixes are refused at startup**: a request matching two routes
has no answer this gateway could give, and resolving it by longest-match is a
rule an operator did not write and cannot see. The prefix is removed before the
request is forwarded, and travels on as `X-Forwarded-Prefix` to what the gateway
serves beneath it rather than to the upstream, which is sent none of the
incoming headers.

`name` is a label. It appears in logs and nowhere else, and it is **not** a Rail
Center data source slug.

**These components front MCP servers only.** The enforcement layer judges `POST`
alone, resolution reads a JSON-RPC body, and the proxy beneath speaks MCP — an
HTTP API behind this gateway is forwarded but never judged.

How a call to a route becomes the key a policy binds, and the constraint that
places on which upstreams can share one gateway, is in
[gateway-core](../gateway-core/README.md#endpoint-keys-and-the-constraint-they-place-on-you).

## Build the image

From the repository root:

```bash
docker build -f gateway-standalone/Dockerfile -t gateway .
```
