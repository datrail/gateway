#!/usr/bin/env bash
# Starts and ends a paid Apigee session (the apigee-session root). The
# environment is billed from `up` until `down`.
#
# Usage: ./session.sh up | down
#   up    builds and pushes the callout's and the stubs' images, applies the
#         root, then waits until a call through the enforce proxy reaches the
#         upstream stub.
#   down  terraform destroy, then lists the org's environments, which must be [].
# ../apigee-org must be applied first, once (README.md).
set -euo pipefail
live=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$live/../../.." && pwd)
cd "$live/apigee-session"
[[ -f terraform.tfvars ]] || { echo "Copy apigee-session/terraform.tfvars.example to terraform.tfvars first." >&2; exit 1; }

api="https://apigee.googleapis.com/v1"
get() { curl -fsS -H "Authorization: Bearer $(gcloud auth print-access-token)" "${api}/$1"; }
elapsed() { local s=$(($(date +%s) - $1)); echo "$((s / 60))m $((s % 60))s"; }
# The org is named after the project.
org="organizations/$(sed -n 's/^project_id *= *"\(.*\)"/\1/p' terraform.tfvars)"

build_images() {
  local registry wiremock
  registry=$(terraform output -raw registry)
  wiremock=$(sed -n 's/^ *image: \(wiremock\/wiremock:.*\)$/\1/p' "$repo/e2e/shared/services.yml")
  gcloud auth configure-docker "${registry%%/*}" --quiet >/dev/null
  # Cloud Run runs linux/amd64, whatever the machine building.
  docker build --platform linux/amd64 -t "$registry/callout:session" \
    -f "$repo/gateway-apigee-grpc/Dockerfile" "$repo"
  docker build --platform linux/amd64 -t "$registry/rail-center:session" \
    -f "$live/stub.Dockerfile" --build-arg "WIREMOCK=$wiremock" "$repo/e2e/shared/rc-mappings"
  docker build --platform linux/amd64 -t "$registry/upstream:session" \
    -f "$live/stub.Dockerfile" --build-arg "WIREMOCK=$wiremock" "$repo/e2e/shared/mcp-mappings"
  for image in callout rail-center upstream; do
    docker push --quiet "$registry/$image:session"
  done
}

# The load balancer, the environment's attachment and new IAM grants each take
# minutes to apply. The upstream stub answers a GET with 405 "stream not
# offered"; anything else is something still starting.
await_proxy() {
  local cert url body
  cert=$(mktemp)
  terraform output -raw lb_cert > "$cert"
  url=$(terraform output -raw enforce_url)
  for _ in $(seq 60); do
    body=$(curl -s --cacert "$cert" "$url" || true)
    if [[ "$body" == *"stream not offered"* ]]; then
      rm -f "$cert"
      return 0
    fi
    sleep 10
  done
  rm -f "$cert"
  echo "The enforce proxy still doesn't reach the upstream stub after 10 minutes. Last answer:" >&2
  echo "$body" >&2
  return 1
}

action=${1:-}
start=$(date +%s)
case "$action" in
  up)
    echo "Session start: $(date '+%F %T %Z'). The environment is billed until ./session.sh down."
    terraform init -input=false >/dev/null
    # The registry first: the services are deployed from images pushed to it.
    terraform apply -auto-approve -input=false \
      -target=google_artifact_registry_repository.images
    build_images
    terraform apply -auto-approve -input=false
    echo
    echo "== Deployments"
    # Base environments only take Standard policies.
    for deployment in $(terraform output -json deployments | jq -r '.[]'); do
      get "$deployment" | jq -c '{revision, state, proxyDeploymentType, serviceAccount}'
    done
    echo
    echo "== Waiting for the enforce proxy to reach the upstream stub"
    await_proxy
    echo "Session up in $(elapsed "$start")."
    echo "END THE SESSION WITH ./session.sh down: the environment is billed while it exists."
    ;;
  down)
    terraform destroy -auto-approve -input=false
    echo
    echo "Session down in $(elapsed "$start")."
    envs=$(get "${org}/environments" | jq -c '.')
    echo "Environments left in the org: ${envs}"
    if [[ "$envs" != "[]" ]]; then
      echo "WARNING: environments are billed while they exist." >&2
      exit 1
    fi
    ;;
  *)
    sed -n '5,9p' "$0" >&2
    exit 1
    ;;
esac
