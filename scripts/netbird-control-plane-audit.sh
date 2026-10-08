#!/usr/bin/env bash
# Read-only control-plane audit. Build first with nice -n 19 make build.
# NB selects the operator's existing NetBird client; no server is installed.
set -euo pipefail
cd "$(dirname "$0")/.."
ts_orch=${TS_ORCH:-dist/ts-orch}
if [[ ! -x $ts_orch ]]; then
	printf 'Build the operator CLI first: nice -n 19 make build\n' >&2
	exit 1
fi
args=()
if [[ -n ${NB:-} ]]; then args+=(--netbird "$NB"); fi
exec "$ts_orch" netbird path-audit "${args[@]}" "$@"
