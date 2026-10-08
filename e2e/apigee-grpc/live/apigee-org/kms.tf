# The keys that encrypt the org's runtime database and the instance's disk.
# Imported: a key ring can't be deleted, so these outlive every teardown, and
# the org and instance are tied to them.

resource "google_kms_key_ring" "apigee" {
  name     = "${var.prefix}-apigee"
  location = var.region
}

resource "google_kms_crypto_key" "apigee" {
  for_each = toset(["runtime-db", "disk"])

  name     = "${var.prefix}-${each.key}"
  key_ring = google_kms_key_ring.apigee.id
  purpose  = "ENCRYPT_DECRYPT"

  # Destroying a key destroys its versions, and the org's data with them.
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "apigee" {
  for_each = google_kms_crypto_key.apigee

  crypto_key_id = each.value.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = google_project_service_identity.apigee.member
}
