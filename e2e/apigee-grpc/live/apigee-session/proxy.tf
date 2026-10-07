# The proxy mcp-g2: renders
# ../../apigee-proxy/mcp-g2/apiproxy for var.mode, zips it, imports it as a
# revision and deploys that to the environment as g2p-apigee-proxy-sa.

locals {
  bundle_dir = "${path.module}/../../apigee-proxy/mcp-g2/apiproxy"

  # passthrough leaves out the policies.
  bundle_files = concat(
    ["mcp-g2.xml", "proxies/default.xml", "targets/default.xml"],
    var.mode == "rail" ? tolist(fileset(local.bundle_dir, "policies/*.xml")) : [],
  )

  description = join(", ", compact([
    "mode ${var.mode}",
    var.mode == "rail" && !var.rail_with_request_headers ? "request headers off" : "",
  ]))

  # passthrough also drops the rail:start … rail:end blocks, leaving only the
  # route to the target.
  bundle_source = {
    for f in local.bundle_files : f => var.mode == "rail" ? file("${local.bundle_dir}/${f}") : replace(
      file("${local.bundle_dir}/${f}"),
      "/(?s)[ \\t]*<!-- rail:start -->.*?<!-- rail:end -->\\n/", "",
    )
  }

  # The __PLACEHOLDERS__ filled in. Terraform has no loop over replacements,
  # hence the nesting.
  bundle = {
    for f, text in local.bundle_source : f =>
    replace(replace(replace(replace(replace(replace(text,
      "__MCP_HOST__", local.mcp_host),
      "__CALLOUT_SERVER__", local.callout_name),
      "__CALLOUT_HOST__", local.callout_host),
      "__RAIL_TIMEOUT_MS__", tostring(var.rail_timeout_ms)),
      "__WITH_REQUEST_HEADERS__", tostring(var.rail_with_request_headers)),
    "__DESCRIPTION__", local.description)
  }
}

# The same zip for the same files, so an unchanged bundle isn't re-imported.
data "archive_file" "bundle" {
  type        = "zip"
  output_path = "${path.module}/.build/mcp-g2.zip"

  dynamic "source" {
    for_each = local.bundle
    content {
      filename = "apiproxy/${source.key}"
      content  = source.value
    }
  }
}

# Each change to the bundle is imported as a new revision (detect_md5hash).
# Unlike with the scripts, the proxy is deleted with the session; importing
# it again takes seconds, and revision numbers restart at 1.
resource "google_apigee_api" "proxy" {
  name           = "mcp-g2"
  org_id         = local.org
  config_bundle  = data.archive_file.bundle.output_path
  detect_md5hash = data.archive_file.bundle.output_md5
}

# Apigee mints the callout's ID token as the service account. A new revision
# replaces this deployment: the old one is undeployed, then the new deployed.
resource "google_apigee_environment_api_revision_deployment" "proxy" {
  org_id          = local.org
  environment     = google_apigee_environment.env.name
  api             = google_apigee_api.proxy.name
  revision        = google_apigee_api.proxy.latest_revision_id
  service_account = local.proxy_sa
  override        = true

  # A deployment only becomes READY on an instance that serves the
  # environment, and EC-Rail needs its TargetServer.
  depends_on = [
    google_apigee_instance_attachment.env,
    google_apigee_envgroup_attachment.env,
    google_apigee_target_server.rail_callout,
  ]
}
