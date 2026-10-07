# g2p-rail-callout, the ExternalCallout gRPC service. Built by
# ../build.sh rail-callout into the repo the agent-gateway root creates, and
# deployed by digest: a new build shows up as a change in terraform plan.
data "google_artifact_registry_docker_image" "rail_callout" {
  location      = var.region
  repository_id = "${var.prefix}-images"
  image_name    = "${var.prefix}-rail-callout:latest"
}

resource "google_cloud_run_v2_service" "rail_callout" {
  name     = "${var.prefix}-rail-callout"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL" # --ingress all

  deletion_protection = false

  template {
    service_account = google_service_account.sa["rail-callout"].email

    # No scaling block: the default is min 0 instances (--min-instances 0;
    # cold starts are a finding). Setting 0 explicitly shows as a change on
    # every plan, because the API doesn't return the block.

    containers {
      image = data.google_artifact_registry_docker_image.rail_callout.self_link

      # gRPC needs HTTP/2 end to end (--use-http2).
      ports {
        name           = "h2c"
        container_port = 8080
      }
    }
  }

  depends_on = [google_project_service.apis]
}

# The account Terraform runs as, i.e. you, for scripts/apigee-callout-test.sh.
data "google_client_openid_userinfo" "me" {}

# No allUsers: every caller needs roles/run.invoker. Apigee calls as the
# proxy's service account.
resource "google_cloud_run_v2_service_iam_member" "rail_callout_invoker" {
  for_each = {
    me    = "user:${data.google_client_openid_userinfo.me.email}"
    proxy = google_service_account.sa["apigee-proxy"].member
  }

  name     = google_cloud_run_v2_service.rail_callout.name
  location = google_cloud_run_v2_service.rail_callout.location
  role     = "roles/run.invoker"
  member   = each.value
}
