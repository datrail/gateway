# A paid session (apigee-plan.md §2.6): the
# environment, its attachments and the callout's TargetServer. The environment
# is billed from creation until terraform destroy (../session.sh down).

data "google_project" "this" {}

locals {
  org    = var.project_id
  org_id = "organizations/${var.project_id}"
  # The deterministic Cloud Run hosts (see ../agent-gateway/mcp-server.tf).
  run_suffix   = "${data.google_project.this.number}.${var.region}.run.app"
  mcp_host     = "${var.prefix}-mcp-server-${local.run_suffix}"
  callout_name = "${var.prefix}-rail-callout"
  callout_host = "${local.callout_name}-${local.run_suffix}"
  proxy_sa     = "${var.prefix}-apigee-proxy-sa@${var.project_id}.iam.gserviceaccount.com"
}

resource "google_apigee_environment" "env" {
  name   = var.apigee_env
  org_id = local.org_id
  type   = var.apigee_env_type
}

# Makes the instance serve the environment. The slow part: several minutes.
resource "google_apigee_instance_attachment" "env" {
  instance_id = "${local.org_id}/instances/${var.apigee_instance}"
  environment = google_apigee_environment.env.name
}

# Routes the envgroup's hostname to the environment.
resource "google_apigee_envgroup_attachment" "env" {
  envgroup_id = "${local.org_id}/envgroups/${var.apigee_envgroup}"
  environment = google_apigee_environment.env.name
}

# Where EC-Rail finds the callout: gRPC over TLS on Cloud Run.
resource "google_apigee_target_server" "rail_callout" {
  name       = local.callout_name
  env_id     = google_apigee_environment.env.id
  host       = local.callout_host
  port       = 443
  protocol   = "EXTERNAL_CALLOUT"
  is_enabled = true

  s_sl_info {
    enabled = true
  }
}
