# Inputs. Values are in terraform.tfvars.

variable "project_id" {
  description = "GCP project ID."
  type        = string
}

variable "region" {
  description = "Region for every regional resource."
  type        = string
}

variable "prefix" {
  description = "Prefix for every resource name we choose."
  type        = string
}
