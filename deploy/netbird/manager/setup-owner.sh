#!/usr/bin/env bash
# Create the NetBird owner over loopback while the instance still needs setup,
# before Caddy publishes netbird.terrascale.tech. Reads the setup request JSON
# ({"email", "password", "name", "create_pat", "pat_expire_in"}) on stdin and
# prints the response, which holds the owner's one-time PAT, on stdout.
set -euo pipefail

API=http://127.0.0.1:18081/api

[[ $EUID -eq 0 ]] || {
  echo "run as root" >&2
  exit 1
}
[[ "$(hostname -s)" == ts-ops ]] || {
  echo "refusing to run outside ts-ops" >&2
  exit 1
}
[[ "${1:-}" == "" ]] || {
  echo "Usage: setup-owner.sh < request.json > response.json" >&2
  exit 2
}

status=$(curl -fsS "$API/instance")
# python3 is on ts-ops already (netbird-backup); jq is not guaranteed.
setup_required=$(python3 -c 'import json, sys; print(str(json.load(sys.stdin).get("setup_required") is True).lower())' <<<"$status") || {
  echo "setup-owner.sh: unexpected instance status: $status" >&2
  exit 1
}
[[ "$setup_required" == true ]] || {
  echo "setup-owner.sh: instance is already set up: $status" >&2
  exit 1
}
curl -fsS -X POST "$API/setup" -H 'Content-Type: application/json' --data-binary @-
