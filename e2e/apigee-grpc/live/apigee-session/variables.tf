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
  description = "Name of the Apigee instance (../apigee-org)."
  type        = string
}

variable "apigee_hostname" {
  description = "Hostname of the environment group. The load balancer rewrites Host to it."
  type        = string
}

variable "apigee_env_type" {
  description = "BASE, INTERMEDIATE or COMPREHENSIVE. The reference bundle needs only BASE."
  type        = string
  default     = "BASE"
}

variable "timeout_ms" {
  description = "How long the proxy waits for the callout (EC-Rail's TimeoutMs)."
  type        = number
  default     = 5000
}
