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
  description = "Name of the Apigee environment group (created by ../apigee-callout-lb)."
  type        = string
}

variable "apigee_env" {
  description = "Name of the environment. It is billed while it exists."
  type        = string
}

variable "apigee_env_type" {
  description = "BASE, INTERMEDIATE or COMPREHENSIVE. BASE only runs Standard policies."
  type        = string
}

variable "rail_timeout_ms" {
  description = "How long the proxy waits for the rail callout."
  type        = number
}

variable "mode" {
  description = "passthrough: the route to the target only. rail: with the callout (EC-Rail, RF-Deny, RF-CalloutFailed)."
  type        = string
  default     = "rail"

  validation {
    condition     = contains(["passthrough", "rail"], var.mode)
    error_message = "mode must be passthrough or rail."
  }
}

variable "rail_with_request_headers" {
  description = "Whether EC-Rail sends the request headers to the callout (scripts/apigee-test.sh headers-off sets false)."
  type        = bool
  default     = true
}
