# What the org needs from the project: the APIs and Apigee's service
# identity. The session's own APIs are in ../apigee-session.

resource "google_project_service" "apis" {
  for_each = toset([
    "apigee.googleapis.com",
    "apihub.googleapis.com",
    "cloudkms.googleapis.com",
  ])

  service = each.key
  # Left enabled on destroy: other work in the project may use them.
  disable_on_destroy = false
}

# Apigee's service agent (service-<N>@gcp-sa-apigee), which uses the KMS keys.
# It exists already; creating it again returns the same identity.
resource "google_project_service_identity" "apigee" {
  provider = google-beta
  service  = "apigee.googleapis.com"

  depends_on = [google_project_service.apis]
}
