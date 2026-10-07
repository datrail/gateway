# Which Terraform and which provider versions this configuration works with.
# `terraform init` downloads the providers and records the exact versions in
# .terraform.lock.hcl, so every run uses the same ones until you upgrade.
terraform {
  required_version = ">= 1.5"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.4" # any 8.x from 8.4 on, never 9.0
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.1"
    }
  }
}
