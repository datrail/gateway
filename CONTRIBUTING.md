# Contributing to the DatRail gateway

The gateway is DatRail's enforcement point: it parses the `x-rail` ticket, allows or refuses the call, and reports the refusal.

## Before you write code

Open an issue first for anything beyond an obvious fix. Anything that changes when a request is allowed belongs in an issue first, with the case you are trying to permit stated plainly.

## Two rules that are not negotiable

**1. It fails closed.** If the gateway cannot decide — unreachable control
plane, malformed policy, unparseable ticket, internal error — the answer is
refuse. A change that introduces any path where an undecidable request proceeds
will be declined.

**2. Every decision is reported.** A denial that is not recorded is close to a
denial that did not happen; the reports are the audit trail.

When you add a rule, add the case that must still be refused. Enforcement code
fails silently in the permissive direction, which is the direction nobody
notices.

## Sending a change

- One coherent change per pull request, with a message that says *why* — the
  diff already says what.
- Branch from `main`.
- **Sign off your commits** (`git commit -s`). We use the
  [Developer Certificate of Origin](https://developercertificate.org/); the
  sign-off is your statement that you wrote the change or have the right to
  contribute it. No CLA.

## Reporting a vulnerability

Not here — see [SECURITY.md](SECURITY.md), and please do not open a public
issue.
