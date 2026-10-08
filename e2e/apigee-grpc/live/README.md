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
| `apigee-session` | the environment and its group, the TargetServers, the two proxies from the reference bundle, the load balancer in front of Apigee and its VPC, the image registry, the service accounts, and on Cloud Run the callout and the `rail-center` and `upstream` stubs | one session: `make e2e-apigee-live-up` to `make e2e-apigee-live-down` | a Base environment, about $0.50 an hour, and the load balancer |

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

Needs `gcloud`, `terraform`, `docker` and `jq`, and `apigee-org` applied.

```sh
cd e2e/apigee-grpc/live/apigee-session
cp terraform.tfvars.example terraform.tfvars   # your values
cd -
make e2e-apigee-live-up     # builds and pushes the images, applies, waits for the proxy
make e2e-apigee-live-down   # destroys everything, then checks no environment is left
```

## Auth and TLS

| Hop | Auth |
|---|---|
| agent (the driver) → load balancer | none; HTTPS with a self-signed certificate |
| Apigee → callout | an ID token from `EC-Rail`, checked by Cloud Run; invokers: the proxy's service account and you |
| callout → `rail-center` | `Bearer e2e-enforce`, which picks the stub's bundle; Cloud Run's IAM check is off |
| Apigee → `upstream` | the agent's `Authorization`, forwarded as sent; Cloud Run's IAM check is off |
| driver → each stub's `/__admin` | basic auth, user `e2e`, password `terraform output -raw stub_admin_password` |

- **The stubs have Cloud Run's IAM check off** because the credentials they
  are called with go in `Authorization`, where Cloud Run would want an ID
  token. The agent's is a fake value, so `upstream`'s journal can show
  whether Apigee forwarded it unchanged. The project's org policies must
  allow `invoker_iam_disabled`.
- **Exposed during a session:** the proxies and the stubs' endpoints, open to
  anyone. They serve fake bundles and fake MCP answers; no real credential
  is used past Apigee.
- **The load balancer's certificate is self-signed** for its IP: a
  Google-managed one needs a DNS name. Clients trust it from
  `terraform output -raw lb_cert` (`curl --cacert`).
