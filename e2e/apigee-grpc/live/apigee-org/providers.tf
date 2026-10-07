# Defaults for every google resource: resources that don't set project or
# region use these. Credentials come from Application Default Credentials
# (gcloud auth application-default login).
provider "google" {
  project = var.project_id
  region  = var.region
}

# Same defaults for the few resources only google-beta has.
provider "google-beta" {
  project = var.project_id
  region  = var.region
}
