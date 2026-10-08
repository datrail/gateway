# Printed after terraform apply. The other roots find the org and instance by
# name (data "google_apigee_instance"), not through these.

output "org_id" {
  value = google_apigee_organization.org.id
}

output "instance_id" {
  value = google_apigee_instance.instance.id
}

# The PSC service attachment the load balancer's NEG connects to.
output "service_attachment" {
  value = google_apigee_instance.instance.service_attachment
}
