#!/usr/bin/env bash
# Starts and ends a paid Apigee session (the apigee-session root). The
# environment is billed from `up` until `down`.
#
# Usage: ./session.sh up [passthrough|rail]   (default rail)
#        ./session.sh down
#   up    terraform apply: the environment, its attachments, the callout's
#         TargetServer and the proxy in that mode. Run it again with the other
#         mode to switch; only the proxy changes.
#   down  terraform destroy, then lists the org's environments, which must be [].
# The other roots must be applied first: apigee-org, apigee-callout-lb.
set -euo pipefail
cd "$(dirname "$0")/apigee-session"

api="https://apigee.googleapis.com/v1"
get() { curl -fsS -H "Authorization: Bearer $(gcloud auth print-access-token)" "${api}/$1"; }
elapsed() { local s=$(($(date +%s) - $1)); echo "$((s / 60))m $((s % 60))s"; }

action=${1:-}
start=$(date +%s)
case "$action" in
  up)
    mode=${2:-rail}
    echo "Session start: $(date '+%F %T %Z'). The environment is billed until ./session.sh down."
    terraform apply -auto-approve -input=false -var "mode=${mode}"
    echo
    echo "== Deployment"
    # Base environments only take Standard proxies (apigee-plan.md §6).
    get "$(terraform output -raw deployment)" | jq '{revision, state, proxyDeploymentType, serviceAccount}'
    echo
    echo "Session up in $(elapsed "$start") ($(terraform output -raw mode))."
    echo "Next: ../scripts/apigee-test.sh …, ../scripts/apigee-logs.sh"
    echo "END THE SESSION WITH ./session.sh down: the environment is billed while it exists."
    ;;
  down)
    # The org is named after the project.
    org="organizations/$(sed -n 's/^project_id *= *"\(.*\)"/\1/p' terraform.tfvars)"
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
    sed -n '5,6p' "$0" >&2
    exit 1
    ;;
esac
