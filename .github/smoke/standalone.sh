#!/bin/sh
# Usage: standalone.sh <image>. Runs it on a non-default port, with Rail Center
# unreachable: it must serve /health and answer /ready with 503.
set -eu

docker run -d --name smoke -p 9100:9100 \
  -e RAIL_GATEWAY_PORT=9100 \
  -e RAIL_PLUGIN_ENABLED=true \
  -e RAIL_CENTER_URL=http://rail-center.invalid \
  -e RAIL_GATEWAY_SLUG=edge \
  -e RAIL_GATEWAY_ROUTES_FILE=/etc/rail/routes.yaml \
  -v "$PWD/e2e/standalone/routes.yaml:/etc/rail/routes.yaml:ro" "$1"

# Startup waits up to 5s for a first bundle fetch; 40 tries is margin.
curl -fsS -o /dev/null --retry 40 --retry-delay 1 --retry-all-errors \
  http://127.0.0.1:9100/health \
  || { echo "::error::the image did not serve /health"; exit 1; }

code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9100/ready)
if [ "$code" != 503 ]; then
  echo "::error::/ready answered $code holding no bundle, expected 503"
  exit 1
fi

docker rm -f smoke >/dev/null
