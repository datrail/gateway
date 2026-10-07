# The reference proxy bundle

An Apigee API proxy that calls the callout for each request: `apiproxy/` is
the bundle, and `targetserver.json` the TargetServer it calls the callout
through. Replace each `__NAME__` before importing them.

| Placeholder | File | Value |
|---|---|---|
| `__PROXY_NAME__` | `apiproxy/rail-mcp.xml` | the name the proxy is imported under |
| `__BASE_PATH__` | `apiproxy/proxies/default.xml` | the path agents call, such as `/mcp`; it is part of every endpoint key the callout judges, so bindings name it |
| `__TARGET_URL__` | `apiproxy/targets/default.xml` | the MCP server's URL, such as `https://mcp.example.com/mcp` |
| `__TIMEOUT_MS__` | `apiproxy/policies/EC-Rail.xml` | how long to wait for the callout, in milliseconds; past it, the proxy answers 503 (`RF-CalloutFailed`) |
| `__CALLOUT_SERVER__` | `EC-Rail.xml`, `targetserver.json` | the TargetServer's name |
| `__CALLOUT_AUDIENCE__` | `EC-Rail.xml` | the callout's URL on Cloud Run, such as `https://rail-callout-123.us-central1.run.app`: the audience of the ID token Apigee sends it |
| `__CALLOUT_HOST__` | `targetserver.json` | the callout's host name |

## Caveats

- **The callout is assumed to run on Cloud Run.** `EC-Rail` sends an ID
  token of the proxy's service account, which Cloud Run checks: give that
  service account `roles/run.invoker` on the callout, and deploy the proxy
  with it. Elsewhere, remove `EC-Rail`'s `<Authentication>`: nothing then
  checks who calls the callout, so keep it reachable only from Apigee.
