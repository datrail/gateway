# What the callout and the load balancer need from the project (the KMS part
# is in ../apigee-org). Nothing here is billed by Apigee.

resource "google_project_service" "apis" {
  for_each = toset([
    "compute.googleapis.com",
    "run.googleapis.com",
    "cloudbuild.googleapis.com",
    "artifactregistry.googleapis.com",
    "iam.googleapis.com",
  ])

  service = each.key
  # terraform destroy leaves the APIs enabled: the other roots and G1 use them.
  disable_on_destroy = false
}

data "google_project" "this" {}

locals {
  org_id = "organizations/${var.project_id}"
  # Apigee's service agent, created with the org (../apigee-org).
  apigee_identity = "serviceAccount:service-${data.google_project.this.number}@gcp-sa-apigee.iam.gserviceaccount.com"
}

# apigee-proxy: the proxy is deployed with it (../apigee-session), and Apigee
# mints the callout's ID token as it. rail-callout: the callout's runtime.
resource "google_service_account" "sa" {
  for_each = toset(["apigee-proxy", "rail-callout"])

  account_id   = "${var.prefix}-${each.key}-sa"
  display_name = "${var.prefix} ${each.key}"

  depends_on = [google_project_service.apis]
}

# May only be needed cross-project (apigee-plan.md §2.2). Granted so the
# session doesn't depend on it.
resource "google_service_account_iam_member" "apigee_on_proxy_sa" {
  service_account_id = google_service_account.sa["apigee-proxy"].name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = local.apigee_identity
}

# For the load balancer's PSC NEG.
resource "google_compute_network" "vpc" {
  name                    = "${var.prefix}-vpc"
  auto_create_subnetworks = false # --subnet-mode custom

  depends_on = [google_project_service.apis]
}

resource "google_compute_subnetwork" "subnet" {
  name          = "${var.prefix}-subnet"
  network       = google_compute_network.vpc.id
  region        = var.region
  ip_cidr_range = "10.20.0.0/24"
}
