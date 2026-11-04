# The callout and the two stubs on Cloud Run, from the images ../session.sh
# pushed as :session, deployed by digest so a new push is a change.

locals {
  images = toset(["callout", "rail-center", "upstream"])
}

data "google_artifact_registry_docker_image" "image" {
  for_each = local.images

  location      = var.region
  repository_id = google_artifact_registry_repository.images.repository_id
  image_name    = "${each.key}:session"
}

resource "random_password" "stub_admin" {
  length  = 32
  special = false
}

# Both stubs are open to anyone: the callout sends its Rail Center credential,
# and the agent its own, in Authorization, where Cloud Run's IAM check would
# want an ID token. Their admin APIs (journal, mappings) need the password.
resource "google_cloud_run_v2_service" "stub" {
  for_each = toset(["rail-center", "upstream"])

  name                 = "${var.prefix}-${each.key}"
  location             = var.region
  deletion_protection  = false
  invoker_iam_disabled = true

  template {
    service_account = google_service_account.sa["stub"].email

    # One instance: WireMock's journal is per instance.
    scaling {
      min_instance_count = 1
      max_instance_count = 1
    }

    containers {
      image = data.google_artifact_registry_docker_image.image[each.key].self_link
      args  = ["--admin-api-basic-auth", "e2e:${random_password.stub_admin.result}"]
    }
  }

  depends_on = [google_project_service.apis]
}

resource "google_cloud_run_v2_service" "callout" {
  name                = "${var.prefix}-callout"
  location            = var.region
  deletion_protection = false

  template {
    service_account = google_service_account.sa["callout"].email

    # Warm, so a cold start can't exceed TimeoutMs and fail a case.
    scaling {
      min_instance_count = 1
    }

    containers {
      image = data.google_artifact_registry_docker_image.image["callout"].self_link

      # gRPC needs HTTP/2 end to end.
      ports {
        name           = "h2c"
        container_port = 8080
      }

      env {
        name  = "RAIL_CENTER_URL"
        value = google_cloud_run_v2_service.stub["rail-center"].uri
      }
      env {
        name  = "RAIL_GATEWAY_SLUG"
        value = "edge"
      }
      env {
        name  = "RAIL_PLUGIN_ENABLED"
        value = "true"
      }
      env {
        name  = "RAIL_AUTH_MODE"
        value = "bearer"
      }
      # Selects the enforce bundle from the stub.
      env {
        name  = "RAIL_AUTH_TOKEN"
        value = "e2e-enforce"
      }

      # Serves only once it holds a bundle.
      startup_probe {
        grpc {
          port    = 8080
          service = "datrail.gateway.Ready"
        }
        period_seconds    = 2
        failure_threshold = 30
      }
    }
  }

  depends_on = [google_project_service.apis]
}

# Apigee calls as the proxy's service account; you, to check it by hand.
resource "google_cloud_run_v2_service_iam_member" "callout_invoker" {
  for_each = {
    me    = local.me
    proxy = google_service_account.sa["proxy"].member
  }

  name     = google_cloud_run_v2_service.callout.name
  location = google_cloud_run_v2_service.callout.location
  role     = "roles/run.invoker"
  member   = each.value
}
