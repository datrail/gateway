# The live harness

Runs the callout's e2e driver against real Apigee X, by hand; never in CI.
Three Terraform roots, applied in this order:

| Root | Holds | Lifetime | Cost |
|---|---|---|---|
| `apigee-org` | the Apigee organisation, its instance, their KMS keys | applied once per project, never destroyed | nothing without an environment, apart from the keys (about $0.06 a month each) |
| `apigee-callout-lb` | the environment group, the load balancer in front of Apigee and its VPC, the service accounts, the callout on Cloud Run | between sessions | the forwarding rule, about $0.60 a day |
| `apigee-session` | the environment, the TargetServer, the proxy | one session: `session.sh up` to `session.sh down` | a Base environment, about $0.50 an hour |

## One-time setup: the Apigee organisation

```sh
cd e2e/apigee-grpc/live/apigee-org
cp terraform.tfvars.example terraform.tfvars   # your project, region and prefix
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
