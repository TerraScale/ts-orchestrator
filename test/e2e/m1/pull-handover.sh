#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
trap 'rm -rf "$work"' EXIT

begin "ordered pull updates: owner handover"
pids=()
for sample in {1..2}; do
	nice -n 19 "$(dirname "$bin")/pull-update" "$bin" handover >"$work/push-$sample.log" 2>&1 &
	pids+=("$!")
done
result=0
for i in "${!pids[@]}"; do
	if wait "${pids[$i]}"; then
		printf 'handover sample %s passed\n' "$((i + 1))"
	else
		printf 'handover sample %s failed\n' "$((i + 1))"
		result=1
	fi
	cat "$work/push-$((i + 1)).log"
done
test "$result" -eq 0
end "a killed owner hands the same durable pull rollout to its successor"
