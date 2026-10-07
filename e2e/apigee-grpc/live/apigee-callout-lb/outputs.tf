# Printed after terraform apply. The scripts in ../../scripts read them with
# terraform output.

output "lb_url" {
  value = "https://${google_compute_global_address.lb.address}/mcp"
}

# The load balancer's self-signed certificate, for curl --cacert.
output "lb_cert" {
  value = tls_self_signed_cert.lb.cert_pem
}

# The deterministic Cloud Run host. apigee-callout-test.sh; the session's
# TargetServer build the same one.
output "rail_callout_host" {
  value = "${google_cloud_run_v2_service.rail_callout.name}-${data.google_project.this.number}.${var.region}.run.app"
}

output "psc_neg" {
  value = google_compute_region_network_endpoint_group.apigee.id
}
