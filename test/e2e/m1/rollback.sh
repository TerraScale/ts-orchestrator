#!/usr/bin/env bash
source "$(dirname "$0")/setup.sh"

begin "never-ready deploy rolls back"
jq '.args = ["--port", "18083"] | .readyTimeoutSeconds = 5' "$here/whoami.json" >"$work/never-ready.json"
if orch service apply -f "$work/never-ready.json" >"$work/apply.txt" 2>&1; then
	cat "$work/apply.txt"
	echo "a never-ready deploy reported success" >&2
	exit 1
fi
cat "$work/apply.txt"
grep -q 'rolled back' "$work/apply.txt"
edge whoami.e2e.test /health
orch events >"$work/events.txt"
grep 'e2e-whoami' "$work/events.txt" | tail -5
grep -q 'service e2e-whoami updated .* update=rollback_completed' "$work/events.txt"
orch service ps e2e-whoami
end "never-ready deploy -> rolled back, previous task serves"
