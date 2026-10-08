# The APIs and identities a session needs. The org's are in ../apigee-org.

resource "google_project_service" "apis" {
  for_each = toset([
    "compute.googleapis.com",
    "run.googleapis.com",
    "artifactregistry.googleapis.com",
    "iam.googleapis.com",
  ])

  service = each.key
  # Left enabled on destroy: other work in the project may use them.
  disable_on_destroy = false
}

data "google_project" "this" {}

# The account Terraform runs as, i.e. you: the driver calls as you.
data "google_client_openid_userinfo" "me" {}

locals {
  org_id = "organizations/${var.project_id}"
  # Apigee's service agent, created with the org (../apigee-org).
  apigee_identity = "serviceAccount:service-${data.google_project.this.number}@gcp-sa-apigee.iam.gserviceaccount.com"
  me              = "user:${data.google_client_openid_userinfo.me.email}"
}

# proxy: the proxies are deployed as it, and Apigee mints the callout's ID
# token as it. callout and stub: the services' runtimes, with no roles.
resource "google_service_account" "sa" {
  for_each = toset(["proxy", "callout", "stub"])

  account_id   = "${var.prefix}-${each.key}-sa"
  display_name = "${var.prefix} ${each.key}"

  depends_on = [google_project_service.apis]
}

# May only be needed cross-project; granted so the session doesn't depend on
# it.
resource "google_service_account_iam_member" "apigee_on_proxy_sa" {
  service_account_id = google_service_account.sa["proxy"].name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = local.apigee_identity
}

# For the load balancer's PSC NEG.
resource "google_compute_network" "vpc" {
  name                    = "${var.prefix}-vpc"
  auto_create_subnetworks = false

  depends_on = [google_project_service.apis]
}

resource "google_compute_subnetwork" "subnet" {
  name          = "${var.prefix}-subnet"
  network       = google_compute_network.vpc.id
  region        = var.region
  ip_cidr_range = "10.20.0.0/24"
}

# The session's images; ../session.sh pushes them before the services are
# applied.
resource "google_artifact_registry_repository" "images" {
  repository_id = "${var.prefix}-images"
  location      = var.region
  format        = "DOCKER"

  depends_on = [google_project_service.apis]
}
