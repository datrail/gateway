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

variable "apigee_instance" {
  description = "Name of the Apigee instance (created by ../apigee-org)."
  type        = string
}

variable "apigee_envgroup" {
  description = "Name of the Apigee environment group."
  type        = string
}

variable "apigee_hostname" {
  description = "Hostname of the environment group. The load balancer rewrites Host to it."
  type        = string
}
