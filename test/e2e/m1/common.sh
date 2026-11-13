#!/usr/bin/env bash
set -euo pipefail

bin=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=$(mktemp -d)
summary=${GITHUB_STEP_SUMMARY:-/dev/stdout}
state=/var/lib/ts-orch
data=/var/lib/ts-data/e2e

timings=()
started=0
begin() { started=$(date +%s%N); echo "::group::$1"; }
end() {
	local ms=$((($(date +%s%N) - started) / 1000000))
	timings+=("| $1 | $((ms / 1000)).$(printf %03d $((ms % 1000))) |")
	echo "::endgroup::"
	echo "$1: ${ms} ms"
}
report() {
	{
		echo "### M1 e2e timings (seconds)"
		echo "| step | s |"
		echo "|---|---|"
		printf '%s\n' "${timings[@]}"
	} >>"$summary"
}

wait_for() {
	local deadline=$((SECONDS + $1))
	shift
	until "$@" >/dev/null 2>&1; do
		((SECONDS < deadline)) || { echo "timed out: $*" >&2; "$@" || true; return 1; }
		sleep 1
	done
}
edge() { curl -fsS --max-time 5 --cacert "$work/ca.pem" --resolve "$1:443:127.0.0.1" "https://$1$2"; }
orch() { sudo /usr/local/bin/ts-orch "$@"; }
dump() {
	echo "::group::diagnostics"
	orch service ls || true
	sudo journalctl -u ts-orch --no-pager -n 200 || true
	sudo cat "$work/ntp-responder.log" 2>/dev/null || true
	echo "::endgroup::"
}
trap dump ERR
trap report EXIT
