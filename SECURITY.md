# Security Policy

The DatRail gateway is the **enforcement point**. It parses the `x-rail` ticket,
decides whether a call is allowed, and reports refusals. If it can be made to
allow a call it should have denied, the entire product has failed — every other
component in DatRail exists to put a trustworthy ticket in front of this one.

Treat a bypass here as the highest-severity class of report we accept.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use the repository's **Security** tab to open a private vulnerability report.

Include what an attacker can do (not only what is wrong), the version or commit,
the smallest reproduction you have, and whether you have told anyone else.

## What to expect

| | |
| --- | --- |
| Acknowledgement | within 3 working days |
| First assessment | within 10 working days |
| Progress | at least every 10 working days until it closes |

We ask for **90 days** before public disclosure and will usually be much
faster. You will be credited unless you would rather not be, and if we disagree
that a report is a vulnerability we will say so plainly rather than let it go
quiet.

## What a bypass looks like

Anything that gets a request past the gateway that should have been refused:

- a **ticket that should not validate** but does — expired, malformed,
  undecodable, absent, or carrying a posture the policy should reject;
- a **parser disagreement**, where the gateway reads a ticket differently from
  the component that issued it, so the identity enforced is not the identity
  intended;
- **fail-open behaviour** under any condition — an unreachable control plane, a
  malformed policy, an internal error. The gateway must refuse when it cannot
  decide, and a path where it does not is a vulnerability even if nothing has
  exploited it;
- a request that reaches the upstream **without a decision being recorded**.
  A denial nobody can see is close to a denial that did not happen.

## Also in scope

- Anything that lets a caller suppress, forge, or flood the denial reports the
  gateway sends — those are the audit trail.
- Header smuggling: a request that presents differently to the gateway than to
  the upstream behind it.

## The Apigee callout

[gateway-apigee-grpc](gateway-apigee-grpc/README.md) sees what standalone
sees, from Apigee rather than from the agent:

- **It receives every request header and the body**, the agent's bearer token
  included. It never logs a header value: an error inside it logs the
  exception's type and frames, not its message.
- **Only Apigee should be able to call it.** A caller could otherwise ask for
  verdicts and send denial reports under this gateway's name. On Cloud Run,
  IAM checks the proxy's ID token: grant `roles/run.invoker` to the proxy's
  service account alone. Elsewhere nothing checks it yet, so keep it
  reachable from Apigee only.
- **The agent's headers reach the upstream**, `Authorization` included,
  except `x-rail` and `x-rail-*`, which the callout removes whatever the
  verdict. An upstream never sees the ticket.

## Scope

In scope: this repository, its images, anything that gets a request past the
gateway that should have been refused, and anything that suppresses or forges
the record of a decision.

Out of scope: vulnerabilities in FastMCP or other dependencies — report those
upstream and we will help; and policy that is permissive because it was
configured that way.
