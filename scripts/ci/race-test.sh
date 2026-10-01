#!/usr/bin/env bash
# Run every race-enabled Go test, with the slowest packages split into shards
# that run beside the rest of the module.
#
# Listing first warms each test binary's Go build cache before any shards
# compete to build it. Top-level tests are dealt round-robin into
# TS_RACE_SHARDS shards; slow process labs get their own shards. Stable -run
# expressions retain Go's test-result cache. TS_RACE_JOBS bounds concurrent
# go test processes; every listed test runs once, and any failure fails CI.
# Vet runs separately over the whole module in make verify/ci-verify.
set -euo pipefail

# GO may be a command with arguments, such as "mise exec -- go".
read -r -a go <<< "${GO:-go}"
shards=${TS_RACE_SHARDS:-6}
jobs=${TS_RACE_JOBS:-6}
sharded_packages=(./internal/app ./internal/bootstrapstart)
# Longest first, so a slow lab cannot get stuck behind short unit shards.
heavy_tests=(
	TestLabTLSHostSessionFencesAndRestartsAfterControllerLoss
	TestControllerThreeProcessBootstrapAndRestart
	TestLabTLSHostSessionRecoversAfterBlackholedController
	TestLabTLSHostSessionRecoversAfterControllerLoss
	TestAuthenticatedOperatorToHostDeliveryWithControllerLoss
)
[[ $shards =~ ^[1-9][0-9]*$ ]] || { echo 'TS_RACE_SHARDS must be a positive integer' >&2; exit 2; }
[[ $jobs =~ ^[1-9][0-9]*$ ]] || { echo 'TS_RACE_JOBS must be a positive integer' >&2; exit 2; }

logs=$(mktemp -d "${TMPDIR:-/tmp}/race-test.XXXXXXXX")
declare -A active=()
failed=0
cleanup() {
	if ((${#active[@]})); then
		kill "${!active[@]}" 2>/dev/null || true
		wait || true
	fi
	rm -rf -- "$logs"
}
trap cleanup EXIT
finish() {
	local completed status
	if wait -n -p completed "${!active[@]}"; then status=ok; else status=FAIL; failed=1; fi
	local name=${active[$completed]}
	printf '=== race %s: %s\n' "$name" "$status"
	cat "$logs/$name.log"
	unset 'active[$completed]'
}
start() {
	local name=$1
	shift
	while ((${#active[@]} >= jobs)); do finish; done
	(
		started=$SECONDS
		status=0
		"$@" || status=$?
		printf 'race %s elapsed=%ss\n' "$name" "$((SECONDS - started))"
		exit "$status"
	) > "$logs/$name.log" 2>&1 &
	active[$!]=$name
}

module=$("${go[@]}" list -m)
"${go[@]}" list ./... > "$logs/packages"
mapfile -t other_packages < <(grep -v -x -F -e "$module/internal/app" -e "$module/internal/bootstrapstart" \
	"$logs/packages")
# Discover all shards before running tests: a failed listing must fail CI,
# and no package has several cold compilers/linkers running simultaneously.
for package in "${sharded_packages[@]}"; do
	if ! "${go[@]}" test -race -vet=off -list '.*' "$package" > "$logs/${package##*/}.list" 2>&1; then
		cat "$logs/${package##*/}.list" >&2
		exit 1
	fi
done
# Script contract packages invoke thousands of bounded subprocesses. Under
# race instrumentation their aggregate can exceed Go's default ten minutes.
start packages "${go[@]}" test -race -vet=off -timeout=20m "${other_packages[@]}"

for package in "${sharded_packages[@]}"; do
	mapfile -t tests < <(grep -E '^(Test|Example|Fuzz)[A-Za-z0-9_]*$' "$logs/${package##*/}.list" | sort)
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
		start "${package##*/}-$shard" "${go[@]}" test -race -vet=off -run "^(${bucket})\$" "$package"
		shard=$((shard + 1))
	done
	[[ $covered == "${#tests[@]}" ]] || { echo "shards of $package cover $covered of ${#tests[@]} tests" >&2; exit 1; }
done

while ((${#active[@]})); do finish; done
exit "$failed"
