# The environment group and the external HTTPS load balancer in front of
# Apigee (apigee-plan.md §2.3). No environment
# here, so nothing Apigee bills for; the forwarding rule costs about $0.60/day.

resource "google_apigee_envgroup" "envgroup" {
  name      = var.apigee_envgroup
  org_id    = local.org_id
  hostnames = [var.apigee_hostname]
}

resource "google_compute_global_address" "lb" {
  name       = "${var.prefix}-apigee-ip"
  ip_version = "IPV4"

  depends_on = [google_project_service.apis]
}

# A self-signed certificate that only needs to match the IP: clients call
# https://<ip>/mcp with --cacert. The private key stays in the local state
# (a prototype; nothing else trusts this certificate).
resource "tls_private_key" "lb" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "lb" {
  private_key_pem = tls_private_key.lb.private_key_pem

  subject {
    common_name = google_compute_global_address.lb.address
  }
  ip_addresses = [google_compute_global_address.lb.address]

  validity_period_hours = 8760 # 1 year
  allowed_uses          = ["digital_signature", "key_encipherment", "server_auth"]
}

# name_prefix and create_before_destroy: a certificate in use by the proxy
# can't be deleted, so a new one is created and swapped in first.
resource "google_compute_ssl_certificate" "lb" {
  name_prefix = "${var.prefix}-apigee-cert-"
  certificate = tls_self_signed_cert.lb.cert_pem
  private_key = tls_private_key.lb.private_key_pem

  lifecycle {
    create_before_destroy = true
  }
}

data "google_apigee_instance" "instance" {
  name   = var.apigee_instance
  org_id = local.org_id
}

# Reaches Apigee over Private Service Connect: the instance's service
# attachment accepts connections from this project (consumer_accept_list in
# ../apigee-org).
resource "google_compute_region_network_endpoint_group" "apigee" {
  name                  = "${var.prefix}-apigee-neg"
  region                = var.region
  network_endpoint_type = "PRIVATE_SERVICE_CONNECT"
  psc_target_service    = data.google_apigee_instance.instance.service_attachment
  network               = google_compute_network.vpc.id
  subnetwork            = google_compute_subnetwork.subnet.id
}

# Apigee's side of the PSC connection speaks TLS with its own certificate,
# which the load balancer doesn't validate.
resource "google_compute_backend_service" "apigee" {
  name                  = "${var.prefix}-apigee-bs"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  protocol              = "HTTPS"

  backend {
    group = google_compute_region_network_endpoint_group.apigee.id
  }

  log_config {
    enable      = true
    sample_rate = 1
  }
}

# Every request goes to Apigee with Host rewritten to the envgroup hostname,
# so clients can call the bare IP.
resource "google_compute_url_map" "apigee" {
  name            = "${var.prefix}-apigee-um"
  default_service = google_compute_backend_service.apigee.id

  default_route_action {
    url_rewrite {
      host_rewrite = var.apigee_hostname
    }
  }
}

resource "google_compute_target_https_proxy" "apigee" {
  name             = "${var.prefix}-apigee-proxy"
  url_map          = google_compute_url_map.apigee.id
  ssl_certificates = [google_compute_ssl_certificate.lb.id]
}

resource "google_compute_global_forwarding_rule" "apigee" {
  name                  = "${var.prefix}-apigee-fr"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  ip_address            = google_compute_global_address.lb.id
  target                = google_compute_target_https_proxy.apigee.id
  port_range            = "443"
}
