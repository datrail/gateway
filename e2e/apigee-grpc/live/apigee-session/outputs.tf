# Printed after terraform apply; ../session.sh reads them.

output "mode" {
  value = local.description
}

output "environment" {
  value = google_apigee_environment.env.id
}

output "revision" {
  value = google_apigee_api.proxy.latest_revision_id
}

# The deployment in the Apigee API (relative to https://apigee.googleapis.com/v1/).
output "deployment" {
  value = "${google_apigee_environment.env.id}/apis/${google_apigee_api.proxy.name}/revisions/${google_apigee_api.proxy.latest_revision_id}/deployments"
}
