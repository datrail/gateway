# Two proxies from the reference bundle: enforce, with the callout, and
# no-callout, whose callout is unreachable. Each is zipped, imported as a
# revision and deployed to the environment as the proxy's service account.

locals {
  bundle_dir = "${path.module}/../../../../gateway-apigee-grpc/apigee/apiproxy"

  proxies = {
    enforce = {
      base_path      = "/mcp"
      callout_server = google_apigee_target_server.callout["callout"].name
    }
    no-callout = {
      base_path      = "/no-callout"
      callout_server = google_apigee_target_server.callout["no-callout"].name
    }
  }

  # Test only: an operator's policy faulting before EC-Rail, on a header.
  operator_fault = "${path.module}/../../RF-E2E-OperatorFault.xml"
  operator_step  = <<-EOT
    <Name>RF-E2E-OperatorFault</Name>
            <Condition>request.header.x-e2e-operator-fault != null</Condition>
          </Step>
          <Step>
            <Name>EC-Rail</Name>
  EOT

  # Each proxy's bundle, the reference bundle's __PLACEHOLDERS__ filled in,
  # plus the operator's policy. Terraform has no loop over replacements,
  # hence the nesting.
  bundles = {
    for proxy, p in local.proxies : proxy => merge(
      {
        for f in fileset(local.bundle_dir, "**/*.xml") : f =>
        replace(replace(replace(replace(replace(replace(replace(file("${local.bundle_dir}/${f}"),
          "__PROXY_NAME__", "${var.prefix}-${proxy}"),
          "__BASE_PATH__", p.base_path),
          "__TARGET_URL__", "${google_cloud_run_v2_service.stub["upstream"].uri}/mcp"),
          "__TIMEOUT_MS__", tostring(var.timeout_ms)),
          "__CALLOUT_SERVER__", p.callout_server),
          "__CALLOUT_AUDIENCE__", google_cloud_run_v2_service.callout.uri),
        "<Name>EC-Rail</Name>", trimspace(local.operator_step))
      },
      { "policies/RF-E2E-OperatorFault.xml" = file(local.operator_fault) },
    )
  }
}

# The same zip for the same files, so an unchanged bundle isn't re-imported.
data "archive_file" "bundle" {
  for_each = local.bundles

  type        = "zip"
  output_path = "${path.module}/.build/${each.key}.zip"

  dynamic "source" {
    for_each = each.value
    content {
      filename = "apiproxy/${source.key}"
      content  = source.value
    }
  }
}

resource "google_apigee_api" "proxy" {
  for_each = local.proxies

  name           = "${var.prefix}-${each.key}"
  org_id         = var.project_id
  config_bundle  = data.archive_file.bundle[each.key].output_path
  detect_md5hash = data.archive_file.bundle[each.key].output_md5
}

# Apigee mints the callout's ID token as the service account.
resource "google_apigee_environment_api_revision_deployment" "proxy" {
  for_each = local.proxies

  org_id          = var.project_id
  environment     = google_apigee_environment.env.name
  api             = google_apigee_api.proxy[each.key].name
  revision        = google_apigee_api.proxy[each.key].latest_revision_id
  service_account = google_service_account.sa["proxy"].email
  override        = true

  # A deployment only becomes READY on an instance that serves the
  # environment.
  depends_on = [
    google_apigee_instance_attachment.env,
    google_apigee_envgroup_attachment.env,
  ]
}
