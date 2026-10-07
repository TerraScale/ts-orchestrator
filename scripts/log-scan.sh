#!/usr/bin/env bash
# Count the WARN and ERROR records TerraScale's services logged in the last
# 20 minutes, per service and node (TS-661). Runs from any operator device in
# the NetBird with ~/.oci/config: it picks this host's NetBird client and
# hands the rest to "ts-orch log-scan", which reads every server peer in the
# NetBird (ts-gru-N, ts-sfo-N, ...). Extra arguments pass through, e.g.
# --since 24h --top 30. Overrides: TS_ORCH, TS_LOG_SCAN_NODES (names),
# TS_LOG_SCAN_FLY_APPS, NB.
set -euo pipefail

cd "$(dirname "$0")/.."
ts_orch=${TS_ORCH:-dist/ts-orch}
[[ -x $ts_orch ]] || make --silent build >&2

vault=ocid1.vault.oc1.sa-saopaulo-1.ffvmfu2naagt6.abtxeljr7ebplea4ua3memgthsupcfn3crg6d56vipsw7o2butchdrx3urmq
nodes=${TS_LOG_SCAN_NODES:-}
# Only ts-dashboard runs on Fly; ts-atlas and ts-status are Cloudflare Workers.
apps=${TS_LOG_SCAN_FLY_APPS-ts-dashboard}

# The NetBird client: NixOS dev VMs (netbird-wt0), the operator automation
# container (deploy/netbird/README.md), else netbird on PATH.
if [[ -z ${NB:-} ]]; then
	if sudo -n netbird-wt0 status >/dev/null 2>&1; then
		NB='sudo -n netbird-wt0'
	elif pid=$(sudo -n podman inspect -f '{{.State.Pid}}' ts-netbird-ops 2>/dev/null); then
		NB="sudo -n env -u SUDO_USER -u SUDO_UID nsenter -t $pid -m /usr/local/bin/netbird"
	else
		NB=netbird
	fi
fi

args=(--vault-id "$vault" --netbird "$NB")
for node in $nodes; do args+=(--node "$node"); done
for app in $apps; do args+=(--fly-app "$app"); done
exec "$ts_orch" log-scan "${args[@]}" "$@"
