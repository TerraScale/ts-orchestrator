#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
trap 'rm -rf "$work"' EXIT

begin "pull updates beside release pushes: preemption, owner handover, a slow worker"
pids=()
for sample in {1..2}; do
	nice -n 19 "$(dirname "$bin")/pull-update" "$bin" push >"$work/push-$sample.log" 2>&1 &
	pids+=("$!")
done
result=0
for i in "${!pids[@]}"; do
	if wait "${pids[$i]}"; then
		printf 'push sample %s passed\n' "$((i + 1))"
	else
		printf 'push sample %s failed\n' "$((i + 1))"
		result=1
	fi
	cat "$work/push-$((i + 1)).log"
done
test "$result" -eq 0
end "a push preempts a pull rollout and wins; a killed owner hands over; the pull never runs beside an in-flight push"
