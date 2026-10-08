# gateway-apigee-grpc

`gateway.apigee_grpc`, an Apigee ExternalCallout service that runs
[gateway-core](../gateway-core/README.md) for an Apigee proxy. Work in progress
(DR-147). See the [main README](../README.md) for the whole.

## Caveats

- **Apigee accepts a callout answer of at most 4 MiB.** Measured on Apigee X
  (2026-10-08); Apigee doesn't document it, and no setting was found to
  raise it. The answer carries the request body back (with no content in
  it, Apigee forwards an empty body), so a call whose body is over about
  4 MiB fails at Apigee after the callout has answered. The
  [reference bundle](apigee/README.md) then answers 503
  `{"error": "policy ruleset cannot be applied"}`, as for an outage, while
  the callout's log shows an ordinary verdict. `RAIL_GATEWAY_GRPC_MAX_MESSAGE_MB`
  doesn't change this. The live e2e driver pins it: a 3.5 MiB call is
  forwarded, a 5 MiB one gets that 503.
