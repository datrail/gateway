# The Apigee org (Pay-as-you-go) and its runtime instance. Neither costs
# anything without an environment; ../apigee-session adds that.
#
# Billing type, peering mode, analytics region and the keys are fixed at
# creation. If a plan wants to replace (-/+) the org or the instance, the code
# here doesn't match what exists: fix the code, never apply.

resource "google_apigee_organization" "org" {
  project_id                           = var.project_id
  runtime_type                         = "CLOUD"
  billing_type                         = "PAYG"
  analytics_region                     = var.region
  disable_vpc_peering                  = true
  runtime_database_encryption_key_name = google_kms_crypto_key.apigee["runtime-db"].id

  # terraform destroy only forgets the org. Deleting a paid org is a soft
  # delete, and no new org can be created in the project until it's gone.
  deletion_policy = "ABANDON"

  depends_on = [google_kms_crypto_key_iam_member.apigee]
}

resource "google_apigee_instance" "instance" {
  name                     = var.apigee_instance
  location                 = var.region
  org_id                   = google_apigee_organization.org.id
  disk_encryption_key_name = google_kms_crypto_key.apigee["disk"].id
  # Projects allowed to connect to the instance's service attachment: ours
  # and Apigee's tenant project, which Apigee adds itself.
  consumer_accept_list = [var.project_id, google_apigee_organization.org.apigee_project_id]

  # Forgotten, not deleted, on destroy: creating it again took ~24 min.
  deletion_policy = "ABANDON"

  timeouts {
    create = "60m"
  }
}
