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

free_cpu() {
	local reserved=0 name
	for name in $(orch service ls | awk 'NR > 1 {print $1}'); do
		reserved=$((reserved + $(orch service inspect "$name" | jq '(.spec.milliCPU // 50) * (.spec.replicas // 1)')))
	done
	echo $(($(nproc) * 1000 - 250 - reserved))
}
fit_spec() {
	jq -n --arg image "$(jq -r .image "$here/whoami.json")" --arg name "$1" --argjson port "$2" --argjson replicas "$3" --argjson cpu "$4" --arg release "$5" \
		'{name: $name, image: $image, env: {WHOAMI_PORT_NUMBER: "${PORT}", E2E_RELEASE: $release}, port: $port, readyPath: "/health", replicas: $replicas, milliCPU: $cpu}'
}
running_tasks() {
	orch service ps "$1" | awk 'NR > 1 && / running +running / {print $1}' | sort | xargs
}
refused="update refused: start-first candidate .* cannot be placed (no suitable node (insufficient resources on 1 node)) without stopping the last of 1 serving tasks"

begin "start-first candidate with no room on the only node is refused, its serving task stays"
fit_spec e2e-fit 18084 1 $(($(free_cpu) / 2 + 1)) 1 >"$work/fit-1.json"
orch service apply -f "$work/fit-1.json"
serving=$(running_tasks e2e-fit)
[[ -n $serving ]]
jq '.env.E2E_RELEASE = "2"' "$work/fit-1.json" >"$work/fit-2.json"
if orch service apply -f "$work/fit-2.json" >"$work/fit.txt" 2>&1; then
	cat "$work/fit.txt"
	echo "an update with no room for its candidate reported success" >&2
	exit 1
fi
cat "$work/fit.txt"
grep -q "$refused; the previous spec is restored" "$work/fit.txt"
only_serving() {
	[[ $(orch service ps e2e-fit | awk 'NR > 1 && / [a-z]+ +running +[0-9hms]+ ago/ {print $1, ($0 ~ / running +running /)}') == "$serving 1" ]]
}
wait_for 30 only_serving
orch service ps e2e-fit
orch service inspect e2e-fit | jq -e '.spec.env.E2E_RELEASE == "1"'
orch service rm e2e-fit
end "unplaceable start-first candidate -> update refused, the same task keeps serving the previous spec"

begin "two replicas with no room for a candidate update one slot at a time, and a candidate that never fits is refused"
free=$(free_cpu)
small=$((free / 3 + 1))
fit_spec e2e-pair 18085 2 "$small" 1 >"$work/pair-1.json"
orch service apply -f "$work/pair-1.json"
fit_spec e2e-pair 18085 2 "$small" 2 >"$work/pair-2.json"
orch service apply -f "$work/pair-2.json"
orch service ps e2e-pair
serving=$(running_tasks e2e-pair)
[[ $(wc -w <<<"$serving") == 2 ]]
orch service inspect e2e-pair | jq -e '.spec.env.E2E_RELEASE == "2"'
fit_spec e2e-pair 18085 2 $((free - small + 1)) 3 >"$work/pair-3.json"
if orch service apply -f "$work/pair-3.json" >"$work/pair.txt" 2>&1; then
	cat "$work/pair.txt"
	echo "an update whose candidate never fits reported success" >&2
	exit 1
fi
cat "$work/pair.txt"
grep -q "$refused; the previous spec is restored" "$work/pair.txt"
kept=$(comm -12 <(tr ' ' '\n' <<<"$serving") <(running_tasks e2e-pair | tr ' ' '\n'))
[[ $(wc -w <<<"$kept") == 1 ]]
pair_restored() {
	[[ $(orch service ps e2e-pair | awk 'NR > 1 && / [a-z]+ +running +[0-9hms]+ ago/ {desired++; running += ($0 ~ / running +running /)} END {print desired + 0, running + 0}') == "2 2" ]]
}
wait_for 30 pair_restored
orch service ps e2e-pair
running_tasks e2e-pair | grep -qw "$kept"
orch service inspect e2e-pair | jq -e '.spec.env.E2E_RELEASE == "2"'
orch service rm e2e-pair
end "two replicas -> stop-first one slot at a time; a never-fitting candidate is refused while an original task keeps serving"

begin "an unplaceable release never hands the serving task to the unserved release it superseded"
fit_spec e2e-over 18086 1 $(($(free_cpu) / 2 + 1)) 1 >"$work/over-1.json"
orch service apply -f "$work/over-1.json"
serving=$(running_tasks e2e-over)
[[ -n $serving ]]
jq '.env.E2E_RELEASE = "2"' "$work/over-1.json" >"$work/over-2.json"
jq '.env.E2E_RELEASE = "3"' "$work/over-1.json" >"$work/over-3.json"
orch service apply -f "$work/over-2.json" >"$work/over-2.txt" 2>&1 &
superseded=$!
second_written() {
	orch service inspect e2e-over | jq -e '.spec.env.E2E_RELEASE == "2"' >/dev/null
}
wait_for 10 second_written
if orch service apply -f "$work/over-3.json" >"$work/over-3.txt" 2>&1; then
	cat "$work/over-3.txt"
	echo "an update with no room for its candidate reported success" >&2
	exit 1
fi
cat "$work/over-3.txt"
grep -q "$refused; they run neither this nor the previous spec" "$work/over-3.txt"
if wait "$superseded"; then
	cat "$work/over-2.txt"
	echo "the superseded release reported success" >&2
	exit 1
fi
cat "$work/over-2.txt"
orch service ps e2e-over
orch service inspect e2e-over | jq -e '.spec.env.E2E_RELEASE == "3"'
[[ $(running_tasks e2e-over) == "$serving" ]]
orch service rm e2e-over
end "release 3 refused while 2 was still unplaced -> neither replaces the serving release 1"

begin "a pending task whose service spec was rewritten is placed once room appears"
fit_spec e2e-hold 18087 1 $(($(free_cpu) / 2 + 1)) 1 >"$work/hold.json"
orch service apply -f "$work/hold.json"
fit_spec e2e-wait 18088 1 "$(jq .milliCPU "$work/hold.json")" 1 >"$work/wait.json"
if orch service apply -f "$work/wait.json" >"$work/wait.txt" 2>&1; then
	cat "$work/wait.txt"
	echo "a service with no room reported ready" >&2
	exit 1
fi
cat "$work/wait.txt"
grep -q "update refused: start-first candidate .* cannot be placed (no suitable node (insufficient resources on 1 node))" "$work/wait.txt"
waiting=$(orch service ps e2e-wait | awk 'NR > 1 && / pending +running / {print $1}')
[[ -n $waiting ]]
fit_spec e2e-nudge 18089 1 50 1 >"$work/nudge.json"
orch service apply -f "$work/nudge.json"
orch service rm e2e-hold
waiting_placed() {
	[[ $(running_tasks e2e-wait) == "$waiting" ]]
}
wait_for 30 waiting_placed
orch service ps e2e-wait
orch service rm e2e-wait
orch service rm e2e-nudge
end "pending task at an older spec version + a failed scheduling pass -> the same task runs once its room frees"

begin "a fixed-port stop-first replacement waits for its predecessor's handoff, past SwarmKit's old-task timer, and nothing else takes its room"
free=$(free_cpu)
handoff=/var/lib/ts-data/e2e-linger
sudo rm -f "$handoff"/handoff-*
jq -n --arg image "$(jq -r .image "$here/data.json")" --argjson cpu $((free / 2 + 1)) \
	'{name: "e2e-linger", image: $image, args: ["sh", "-c", "trap \"stop=1\" TERM; until [ -n \"$stop\" ] && [ -f /tmp/handoff-$E2E_RELEASE ]; do sleep 1; done"], env: {E2E_RELEASE: "1"}, mounts: [{source: "/var/lib/ts-data/e2e-linger", target: "/tmp"}], port: 18090, replicas: 1, milliCPU: $cpu}' >"$work/linger-1.json"
orch service apply -f "$work/linger-1.json"
lingering=$(running_tasks e2e-linger)
[[ -n $lingering ]]
jq '.env.E2E_RELEASE = "2"' "$work/linger-1.json" >"$work/linger-2.json"
orch service apply -f "$work/linger-2.json" >"$work/linger-2.txt" 2>&1 &
replacing=$!
told_to_stop() {
	orch service ps e2e-linger | awk -v id="$lingering" '$1 == id' | grep -Eq ' running +shutdown '
}
no_port_contention() {
	orch service ps e2e-linger >"$work/linger-ps.txt"
	if grep -q 'is reserved' "$work/linger-ps.txt"; then
		cat "$work/linger-ps.txt"
		echo "the replacement tried to take host ports its predecessor still holds" >&2
		exit 1
	fi
}
replacement_waiting() {
	no_port_contention
	awk -v id="$lingering" 'NR > 1 && $1 != id' "$work/linger-ps.txt" | grep -Eq ' (assigned|accepted|preparing|ready) +ready '
}
wait_for 20 told_to_stop
stopping=$SECONDS
wait_for 30 replacement_waiting
fit_spec e2e-room 18091 1 $((free - free / 2)) 1 >"$work/room.json"
if orch service apply -f "$work/room.json" >"$work/room.txt" 2>&1; then
	cat "$work/room.txt"
	echo "a service took the room of a predecessor that still runs" >&2
	exit 1
fi
cat "$work/room.txt"
grep -q "update refused: start-first candidate .* cannot be placed (no suitable node (insufficient resources on 1 node))" "$work/room.txt"
orch service rm e2e-room
while ((SECONDS < stopping + 70)); do
	told_to_stop
	replacement_waiting
	kill -0 "$replacing"
	sleep 5
done
orch service ps e2e-linger
sudo touch "$handoff/handoff-1"
if ! wait "$replacing"; then
	cat "$work/linger-2.txt"
	echo "the replacement did not serve once its predecessor handed over" >&2
	exit 1
fi
cat "$work/linger-2.txt"
replaced=$(running_tasks e2e-linger)
[[ -n $replaced && $replaced != "$lingering" ]]
no_port_contention
sudo touch "$handoff/handoff-2"
orch service rm e2e-linger
end "predecessor refuses its handoff for 70 s after SIGTERM -> the replacement waits ready, never contends for its ports, another service is refused its room; handoff accepted -> the replacement serves"
