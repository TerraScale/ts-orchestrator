#!/usr/bin/env bash
# Run every race-enabled Go test, with the slowest packages split into shards
# that run beside the rest of the module.
#
# Each sharded package's top-level tests are listed and dealt round-robin into
# TS_RACE_SHARDS shards by name; tests named in HEAVY_TESTS get a shard of
# their own. Every listed test runs in exactly one shard, and the shard
# regular expressions are stable, so Go's test cache still skips unchanged
# shards. Shards and the remaining packages run as parallel `go test`
# processes; any failure fails the run after all of them finish.
set -euo pipefail

GO=${GO:-go}
shards=${TS_RACE_SHARDS:-6}
sharded_packages=(./internal/app ./internal/bootstrapstart)
# Tests that alone take over a minute under -race.
heavy_tests=(TestLabTLSHostSessionRecoversAfterControllerLoss TestControllerThreeProcessBootstrapAndRestart)
[[ $shards =~ ^[1-9][0-9]*$ ]] || { echo 'TS_RACE_SHARDS must be a positive integer' >&2; exit 2; }

logs=$(mktemp -d "${TMPDIR:-/tmp}/race-test.XXXXXXXX")
trap 'rm -rf -- "$logs"' EXIT
pids=()
names=()
start() {
	local name=$1
	shift
	"$@" > "$logs/$name.log" 2>&1 &
	pids+=("$!")
	names+=("$name")
}

module=$($GO list -m)
$GO list ./... > "$logs/packages"
mapfile -t other_packages < <(grep -v -x -F -e "$module/internal/app" -e "$module/internal/bootstrapstart" \
	"$logs/packages")
start packages $GO test -race "${other_packages[@]}"

for package in "${sharded_packages[@]}"; do
	$GO test -race -list '.*' "$package" > "$logs/list"
	mapfile -t tests < <(grep -E '^(Test|Example|Fuzz)[A-Za-z0-9_]*$' "$logs/list" | sort)
	((${#tests[@]} > 0)) || { echo "no tests listed in $package" >&2; exit 1; }
	buckets=()
	index=0
	for test in "${tests[@]}"; do
		slot=
		for heavy in "${!heavy_tests[@]}"; do
			[[ $test == "${heavy_tests[heavy]}" ]] && slot=$heavy
		done
		if [[ -z $slot ]]; then
			slot=$((${#heavy_tests[@]} + index % shards))
			index=$((index + 1))
		fi
		buckets[slot]="${buckets[slot]:+${buckets[slot]}|}$test"
	done
	covered=0
	shard=0
	for bucket in "${buckets[@]}"; do
		[[ -n $bucket ]] || continue
		covered=$((covered + $(tr '|' '\n' <<< "$bucket" | wc -l)))
		start "${package##*/}-$shard" $GO test -race -run "^(${bucket})\$" "$package"
		shard=$((shard + 1))
	done
	[[ $covered == "${#tests[@]}" ]] || { echo "shards of $package cover $covered of ${#tests[@]} tests" >&2; exit 1; }
done

failed=0
for position in "${!pids[@]}"; do
	if wait "${pids[position]}"; then status=ok; else status=FAIL; failed=1; fi
	printf '=== race %s: %s\n' "${names[position]}" "$status"
	cat "$logs/${names[position]}.log"
done
exit "$failed"
