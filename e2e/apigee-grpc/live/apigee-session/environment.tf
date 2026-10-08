# The environment, its attachments and the TargetServers. The environment is
# billed from creation until terraform destroy (../session.sh down).

resource "google_apigee_environment" "env" {
  name   = "${var.prefix}-env"
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
  envgroup_id = google_apigee_envgroup.envgroup.id
  environment = google_apigee_environment.env.name
}

# Where EC-Rail finds the callout: gRPC over TLS on Cloud Run. no-callout
# points at a host that never resolves, so EC-Rail always fails there.
resource "google_apigee_target_server" "callout" {
  for_each = {
    callout    = trimprefix(google_cloud_run_v2_service.callout.uri, "https://")
    no-callout = "no-callout.invalid"
  }

  name       = "${var.prefix}-${each.key}"
  env_id     = google_apigee_environment.env.id
  host       = each.value
  port       = 443
  protocol   = "EXTERNAL_CALLOUT"
  is_enabled = true

  s_sl_info {
    enabled = true
  }
}
