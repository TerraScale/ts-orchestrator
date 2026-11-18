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

begin "start-first candidate with no room on the only node is refused, its serving task stays"
reserved=0
for name in $(orch service ls | awk 'NR > 1 {print $1}'); do
	reserved=$((reserved + $(orch service inspect "$name" | jq '.spec.milliCPU // 50')))
done
cpu=$((($(nproc) * 1000 - 250 - reserved) / 2 + 1))
jq -n --arg image "$(jq -r .image "$here/whoami.json")" --argjson cpu "$cpu" \
	'{name: "e2e-fit", image: $image, env: {WHOAMI_PORT_NUMBER: "${PORT}", E2E_RELEASE: "1"}, port: 18084, readyPath: "/health", replicas: 1, milliCPU: $cpu}' >"$work/fit-1.json"
orch service apply -f "$work/fit-1.json"
serving=$(orch service ps e2e-fit | awk 'NR > 1 && / running +running / {print $1}')
[[ -n $serving ]]
jq '.env.E2E_RELEASE = "2"' "$work/fit-1.json" >"$work/fit-2.json"
if orch service apply -f "$work/fit-2.json" >"$work/fit.txt" 2>&1; then
	cat "$work/fit.txt"
	echo "an update with no room for its candidate reported success" >&2
	exit 1
fi
cat "$work/fit.txt"
grep -q "update refused and rolled back: start-first candidate .* cannot be placed (no suitable node (insufficient resources on 1 node)), and stopping first would stop all 1 serving tasks" "$work/fit.txt"
only_serving() {
	[[ $(orch service ps e2e-fit | awk 'NR > 1 && / [a-z]+ +running +[0-9hms]+ ago/ {print $1, ($0 ~ / running +running /)}') == "$serving 1" ]]
}
wait_for 30 only_serving
orch service ps e2e-fit
orch service inspect e2e-fit | jq -e '.spec.env.E2E_RELEASE == "1"'
orch service rm e2e-fit
end "unplaceable start-first candidate -> update refused, the same task keeps serving the previous spec"
