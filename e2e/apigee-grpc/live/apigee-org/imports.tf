# Brings what already exists under Terraform, on the next apply. Once applied,
# these blocks do nothing and can stay: they document where the state came from.

import {
  to = google_kms_key_ring.apigee
  id = "projects/${var.project_id}/locations/${var.region}/keyRings/${var.prefix}-apigee"
}

import {
  for_each = toset(["runtime-db", "disk"])
  to       = google_kms_crypto_key.apigee[each.key]
  id       = "projects/${var.project_id}/locations/${var.region}/keyRings/${var.prefix}-apigee/cryptoKeys/${var.prefix}-${each.key}"
}

import {
  to = google_apigee_organization.org
  id = "organizations/${var.project_id}"
}

import {
  to = google_apigee_instance.instance
  id = "organizations/${var.project_id}/instances/${var.prefix}-usc1"
}
