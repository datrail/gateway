# The live harness

Runs the callout's e2e driver against real Apigee X, by hand; never in CI.

**A test harness, not a deployment template.** It takes shortcuts a
production setup shouldn't: open stubs and proxies, a self-signed
certificate, fake credentials. For deploying the callout, start from
`gateway-apigee-grpc/apigee/` and its README.

Two Terraform roots:

| Root | Holds | Lifetime | Cost |
|---|---|---|---|
| `apigee-org` | the Apigee organisation, its instance, their KMS keys | applied once per project, never destroyed | nothing without an environment, apart from the keys (about $0.06 a month each) |
| `apigee-session` | the environment and its group, the TargetServers, the two proxies from the reference bundle, the load balancer in front of Apigee and its VPC, the image registry, the service accounts, and on Cloud Run the callout and the `rail-center` and `upstream` stubs | one session: `session.sh up` to `session.sh down` | a Base environment, about $0.50 an hour, and the load balancer |

## One-time setup: the Apigee organisation

```sh
cd e2e/apigee-grpc/live/apigee-org
cp terraform.tfvars.example terraform.tfvars   # your values
gcloud auth application-default login
terraform init
terraform apply
```

The state is local (`terraform.tfstate`, not committed), and applying again
with it changes nothing. Without it (lost, another machine, or an
organisation created some other way), adopt what exists instead of creating
it:

```sh
cp imports.tf.example imports.tf   # edit the IDs if yours are named differently
terraform apply                    # imports; creates nothing
rm imports.tf
```

**Keep the organisation and instance: deleting them costs days.** Deleting a
paid organisation is a soft delete lasting many days, and no new one can be
created in the project until it ends. Creating the instance again then takes
about 24 minutes more. Kept, they cost nothing: Apigee bills environments,
which `apigee-session` creates and destroys.  So the root never deletes them:
`deletion_policy = "ABANDON"` makes `terraform destroy` only drop them from the
state, and the KMS keys they depend on have `prevent_destroy`.

## A session

Needs `gcloud`, `terraform`, `docker`, `jq` and `uv`, and `apigee-org`
applied. Owner on the project covers both roots; a narrower set of roles is
untested.

```sh
cd e2e/apigee-grpc/live/apigee-session
cp terraform.tfvars.example terraform.tfvars   # your values
cd ..
./session.sh up     # builds and pushes the images, applies, waits for the proxy
./session.sh test   # runs the driver against the session
./session.sh down   # destroys everything, then checks no environment is left
```

- **Cost:** mostly the Base environment, about $0.50 an hour; the load
  balancer and three always-on Cloud Run instances add a few cents. It is
  billed from `up` until `down`, so **always end with `down`**, which fails
  if any environment is left in the organisation.
- **Time:** a first `up` takes roughly 15 to 25 minutes, most of it the
  environment attaching to the instance. `up` again on a running session
  redeploys what changed (the callout, a stub, the bundle) in about 3
  minutes, so a fix can be tried in the same session.
- **`up` waits** until a `GET` through `enforce` gets the upstream stub's 405,
  for up to 10 minutes, then checks the stubs' `/__admin` refuses a call
  without the password. If the wait times out, it prints the last answer:
  an Apigee fault there names what is wrong.

## What the driver checks

`./session.sh test` runs `../driver.py` with `E2E_TARGET=live`, the
session's URLs, its certificate and the stubs' password, all as `E2E_*`
variables; its exit code is the result. The Apigee cases:
- discovery passes; a call with no ticket is refused 403 with standalone's
  body, and the denial names P0; a good ticket's call is forwarded;
- no `x-rail*` header reaches `upstream`, `accept` arrives whole, and the
  agent's `Authorization` arrives as sent (D3);
- Apigee's own behaviour, as the plan's §9 records it: a ticket split on a
  comma or sent on two header lines is `undecodable`; a claimed status with
  a comma is dropped; a query string stays out of the endpoint key; a body
  that isn't UTF-8 is refused; a 3.5 MiB call is forwarded and a 5 MiB one
  fails closed (the callout README's Caveats);
- `no-callout` answers 503 with `RF-CalloutFailed`'s body, and nothing
  reaches `upstream` (D2);
- an operator's policy faulting before `EC-Rail` keeps its own error, on
  both proxies. The policy, `../RF-E2E-OperatorFault.xml`, is test only:
  the session adds it in front of `EC-Rail`, on header
  `x-e2e-operator-fault`.

**Adding or changing an Apigee case:** run it here first, then on the
stand-in. These cases are the stand-in's specification, so a change to one
needs a live run.

## Auth and TLS

| Hop | Auth |
|---|---|
| agent (the driver) → load balancer | none; HTTPS with a self-signed certificate |
| Apigee → callout | an ID token from `EC-Rail`, checked by Cloud Run; invokers: the proxy's service account and you |
| callout → `rail-center` | `Bearer e2e-enforce`, which picks the stub's bundle; Cloud Run's IAM check is off |
| Apigee → `upstream` | the agent's `Authorization`, forwarded as sent; Cloud Run's IAM check is off |
| driver → each stub's `/__admin` | basic auth, user `e2e`, password `terraform output -raw stub_admin_password` |

- **The stubs have Cloud Run's IAM check off**, because the credentials
  they are called with go in `Authorization`, where Cloud Run would want an
  ID token: the callout's Rail Center credential, and the agent's. Not
  chosen: `X-Serverless-Authorization`, which the callout would have to send
  (product code for a test); internal ingress, which would leave the driver
  no way to read the journals; `RAIL_AUTH_MODE=none`, which Cloud Run would
  still refuse, and with which the stub could no longer pick a bundle by
  credential.
- **The project's org policies** (`iam.allowedPolicyMemberDomains`,
  `run.managed.requireInvokerIam`) must allow `invoker_iam_disabled`; the
  stubs fail to deploy otherwise.
- **The stubs' admin APIs** (journals, mappings) need basic auth, user
  `e2e`, with a password generated for each session. `up` checks a call
  without it gets 401.
- **The agent's credential is fake** (`Bearer e2e-agent`), so `upstream`'s
  journal can show whether Apigee forwarded it unchanged. Behind Cloud Run's
  IAM check it couldn't: Cloud Run strips a checked token's signature before
  the container sees it.
- **The callout keeps Cloud Run's IAM check:** Apigee calls it with an ID
  token of the proxy's service account, as in production. You are an
  invoker too, to call it by hand.
- **The load balancer's certificate is self-signed** for its IP: a
  Google-managed one needs a DNS name. Clients trust it from
  `terraform output -raw lb_cert` (`curl --cacert`).
- **Exposed during a session:** the proxies and the stubs, open to anyone.
  They serve fake bundles and fake MCP answers, and no real credential is
  used past Apigee. Nothing is left once `down` has run.
