#!/usr/bin/env bash
# Run every race-enabled Go test as one queue of shards, longest first.
#
# Listing first warms each test binary's Go build cache before any shards
# compete to build it. TS_RACE_DURATIONS (default: race-durations.txt beside
# this script) estimates what each test costs under the race detector. The
# tests of the slowest packages are packed by that cost into at most
# TS_RACE_SHARDS shards per package, longest test first into the least
# loaded shard; tests marked solo or idle get a shard of their own. Every
# shard, and one shard for all other packages, then joins a single queue
# ordered by estimated cost, so the slowest work starts first.
#
# The assignment depends only on the committed estimates and the listed
# tests, so the -run expressions, and with them Go's test-result cache, stay
# stable between runs. TS_RACE_JOBS bounds concurrent go test processes for
# CPU-bound shards; TS_RACE_IDLE_JOBS more run the process labs that mostly
# wait on real lease and session timers. TS_TEST_TIER=pr runs the fast tier
# (-short); full, the default, runs every tier-gated test as well. Every
# listed test runs once, and any failure fails CI. Vet runs separately over
# the whole module in make verify/ci-verify.
set -euo pipefail
# wait -n -p needs bash 5.1; older shells would fail mid-suite with an
# unbound variable instead of this message.
((BASH_VERSINFO[0] > 5 || BASH_VERSINFO[0] == 5 && BASH_VERSINFO[1] >= 1)) \
	|| { echo "race-test.sh needs bash >= 5.1 (wait -n -p), not $BASH_VERSION" >&2; exit 2; }

# GO may be a command with arguments, such as "mise exec -- go".
read -r -a go <<< "${GO:-go}"
shards=${TS_RACE_SHARDS:-6}
jobs=${TS_RACE_JOBS:-6}
idle_jobs=${TS_RACE_IDLE_JOBS:-5}
package_jobs=${TS_RACE_PACKAGE_JOBS:-4}
test_jobs=${TS_RACE_TEST_JOBS:-2}
tier=${TS_TEST_TIER:-full}
durations=${TS_RACE_DURATIONS:-$(dirname -- "$(realpath -- "$0")")/race-durations.txt}
# The image contract suite drives the offline builder through hundreds of
# command fakes per test; unsharded it serialised most of the CI job.
sharded_packages=(./internal/app ./internal/bootstrapstart ./tests/deploy)
configured_packages=("${sharded_packages[@]}")
# Shard, listing and log names use the package's last element.
declare -A seen_base=()
for package in "${sharded_packages[@]}"; do
	[[ -z ${seen_base[${package##*/}]:-} ]] || { echo "sharded packages share the name ${package##*/}: $package" >&2; exit 2; }
	seen_base[${package##*/}]=1
done
[[ $shards =~ ^[1-9][0-9]*$ ]] || { echo 'TS_RACE_SHARDS must be a positive integer' >&2; exit 2; }
[[ $jobs =~ ^[1-9][0-9]*$ ]] || { echo 'TS_RACE_JOBS must be a positive integer' >&2; exit 2; }
[[ $idle_jobs =~ ^[1-9][0-9]*$ ]] || { echo 'TS_RACE_IDLE_JOBS must be a positive integer' >&2; exit 2; }
[[ $package_jobs =~ ^[1-9][0-9]*$ ]] || { echo 'TS_RACE_PACKAGE_JOBS must be a positive integer' >&2; exit 2; }
[[ $test_jobs =~ ^[1-9][0-9]*$ ]] || { echo 'TS_RACE_TEST_JOBS must be a positive integer' >&2; exit 2; }
case $tier in
	pr) short=(-short) ;;
	full) short=() ;;
	*) echo 'TS_TEST_TIER must be pr or full' >&2; exit 2 ;;
esac
[[ -f $durations && -r $durations ]] || { echo "race durations file is not readable: $durations" >&2; exit 2; }

# Every test binary and re-executed child skips the race runtime's default
# one-second exit sleep; the tests themselves wait for their goroutines.
export GORACE="${GORACE:+$GORACE }atexit_sleep_ms=0"

# Each line: <package> <test or glob> <seconds>[/<seconds under -short>]
# [cpu|solo|idle], or "rest - <seconds>" for the shard of all other
# packages. The first matching line wins; unmatched tests cost one second.
entry_package=()
entry_test=()
entry_cost=()
entry_pool=()
rest_cost=1
line_number=0
while IFS= read -r line || [[ -n $line ]]; do
	line_number=$((line_number + 1))
	line=${line%%#*}
	package='' test='' cost='' pool='' extra=''
	read -r package test cost pool extra <<< "$line" || true
	[[ -n $package ]] || continue
	pool=${pool:-cpu}
	# No leading zeros: arithmetic would read them as octal.
	[[ -n $test && $cost =~ ^(0|[1-9][0-9]*)(/(0|[1-9][0-9]*))?$ && $pool =~ ^(cpu|solo|idle)$ && -z $extra ]] || {
		echo "$durations:$line_number: want <package> <test> <seconds>[/<short seconds>] [cpu|solo|idle]" >&2
		exit 2
	}
	if [[ $tier == pr ]]; then cost=${cost#*/}; else cost=${cost%%/*}; fi
	if [[ $package == rest ]]; then
		rest_cost=$cost
		continue
	fi
	entry_package+=("$package")
	entry_test+=("$test")
	entry_cost+=("$cost")
	entry_pool+=("$pool")
done < "$durations"
estimate() {
	local i
	for i in "${!entry_package[@]}"; do
		# The test column is a glob pattern.
		# shellcheck disable=SC2053
		if [[ ${entry_package[i]} == "$1" && $2 == ${entry_test[i]} ]]; then
			est_cost=${entry_cost[i]}
			est_pool=${entry_pool[i]}
			matched[$i]=1
			return
		fi
	done
	est_cost=1
	est_pool=cpu
}

logs=$(mktemp -d "${TMPDIR:-/tmp}/race-test.XXXXXXXX")
declare -A active=() active_pool=()
running_cpu=0
running_idle=0
failed=0
# Invoked through the EXIT trap.
# shellcheck disable=SC2329
cleanup() {
	local pid
	if ((${#active[@]})); then
		# Each shard leads its own process group (see start), so this also
		# stops its go test and test binary children, not just the subshell.
		for pid in "${!active[@]}"; do
			kill -- "-$pid" 2>/dev/null || true
		done
		wait || true
	fi
	rm -rf -- "$logs"
}
trap cleanup EXIT
finish() {
	local completed= status rc=0 pid
	wait -n -p completed "${!active[@]}" || rc=$?
	if [[ -z $completed ]]; then
		# Some bash releases stop reporting a shard to wait -n once it has
		# already terminated and been marked notified (for example while
		# another shard's log was printed); wait -n then returns 127 without
		# a pid. A plain wait still returns such a shard's saved status.
		for pid in "${!active[@]}"; do
			if ! kill -0 "$pid" 2>/dev/null; then
				completed=$pid
				rc=0
				wait "$pid" || rc=$?
				break
			fi
		done
		if [[ -z $completed ]]; then
			echo "race-test.sh: wait -n reported no finished shard (status $rc)" >&2
			exit 2
		fi
	fi
	if ((rc == 0)); then status=ok; else status=FAIL; failed=1; fi
	local name=${active[$completed]}
	if [[ ${active_pool[$completed]} == idle ]]; then
		running_idle=$((running_idle - 1))
	else
		running_cpu=$((running_cpu - 1))
	fi
	printf '=== race %s: %s\n' "$name" "$status"
	cat "$logs/$name.log"
	unset 'active[$completed]' 'active_pool[$completed]'
}
available() {
	if [[ $1 == idle ]]; then ((running_idle < idle_jobs)); else ((running_cpu < jobs)); fi
}
start() {
	local name=$1 pool=$2
	shift 2
	printf 'race start %s pool=%s\n' "$name" "$pool"
	# Job control gives the shard its own process group, so cleanup can stop
	# the whole tree after an abnormal exit.
	set -m
	(
		started=$SECONDS
		status=0
		"$@" || status=$?
		printf 'race %s elapsed=%ss\n' "$name" "$((SECONDS - started))"
		exit "$status"
	) > "$logs/$name.log" 2>&1 &
	set +m
	active[$!]=$name
	active_pool[$!]=$pool
	if [[ $pool == idle ]]; then running_idle=$((running_idle + 1)); else running_cpu=$((running_cpu + 1)); fi
}

module=$("${go[@]}" list -m)
"${go[@]}" list ./... > "$logs/packages"
present=()
for package in "${sharded_packages[@]}"; do
	if grep -q -x -F -e "$module/${package#./}" "$logs/packages"; then
		present+=("$package")
		printf '%s\n' "$module/${package#./}"
	fi
done > "$logs/sharded"
sharded_packages=("${present[@]}")
mapfile -t other_packages < <(grep -v -x -F -f "$logs/sharded" "$logs/packages")
# Discover all shards before running tests: a failed listing must fail CI,
# and no package has several cold compilers/linkers running simultaneously.
for package in "${sharded_packages[@]}"; do
	if ! "${go[@]}" test -race -vet=off -list '.*' "$package" > "$logs/${package##*/}.list" 2>&1; then
		cat "$logs/${package##*/}.list" >&2
		exit 1
	fi
done

# Queue lines: <estimated seconds> <shard name> <pool> <package> <-run expression>.
tab=$'\t'
declare -A matched=()
: > "$logs/queue"
if ((${#other_packages[@]})); then
	printf '%s\tpackages\tcpu\t\t\n' "$rest_cost" >> "$logs/queue"
fi
for package in "${sharded_packages[@]}"; do
	base=${package##*/}
	mapfile -t tests < <(grep -E '^(Test|Example|Fuzz)[A-Za-z0-9_]*$' "$logs/$base.list" | LC_ALL=C sort)
	((${#tests[@]} > 0)) || { echo "no tests listed in $package" >&2; exit 1; }
	: > "$logs/$base.packed"
	covered=0
	for test in "${tests[@]}"; do
		estimate "$package" "$test"
		if [[ $est_pool == cpu ]]; then
			printf '%s %s\n' "$est_cost" "$test" >> "$logs/$base.packed"
		else
			printf '%s\t%s-%s\t%s\t%s\t^(%s)$\n' "$est_cost" "$base" "$test" "${est_pool/solo/cpu}" "$package" "$test" >> "$logs/queue"
			covered=$((covered + 1))
		fi
	done
	# Longest processing time first: each test joins the shard with the least
	# estimated work so far, or the fewest tests when estimates tie.
	loads=()
	counts=()
	members=()
	for ((bin = 0; bin < shards; bin++)); do loads[bin]=0; counts[bin]=0; members[bin]=; done
	while read -r cost test; do
		best=0
		for ((bin = 1; bin < shards; bin++)); do
			if ((loads[bin] < loads[best] || (loads[bin] == loads[best] && counts[bin] < counts[best]))); then
				best=$bin
			fi
		done
		loads[best]=$((loads[best] + cost))
		counts[best]=$((counts[best] + 1))
		members[best]="${members[best]:+${members[best]}|}$test"
	done < <(LC_ALL=C sort -k1,1nr -k2,2 "$logs/$base.packed")
	shard=0
	for ((bin = 0; bin < shards; bin++)); do
		[[ -n ${members[bin]} ]] || continue
		expression=$(tr '|' '\n' <<< "${members[bin]}" | LC_ALL=C sort | paste -s -d '|')
		covered=$((covered + $(tr '|' '\n' <<< "$expression" | wc -l)))
		printf '%s\t%s-%s\t%s\t%s\t^(%s)$\n' "${loads[bin]}" "$base" "$shard" cpu "$package" "$expression" >> "$logs/queue"
		shard=$((shard + 1))
	done
	[[ $covered == "${#tests[@]}" ]] || { echo "shards of $package cover $covered of ${#tests[@]} tests" >&2; exit 1; }
done
mapfile -t queue < <(LC_ALL=C sort -t "$tab" -k1,1nr -k2,2 "$logs/queue")
printf 'race plan tier=%s cpu_jobs=%s idle_jobs=%s shards=%s\n' "$tier" "$jobs" "$idle_jobs" "${#queue[@]}"
for entry in "${queue[@]}"; do
	IFS="$tab" read -r cost name pool _ _ <<< "$entry"
	printf 'race queue %s pool=%s estimate=%ss\n' "$name" "$pool" "$cost"
done
# Estimates must stay live like every other input: an entry naming no
# sharded package can never apply, and a named test that matches no listed
# test (renamed, removed, or shadowed by an earlier line) has gone stale.
stale=0
for i in "${!entry_package[@]}"; do
	[[ -z ${matched[$i]:-} ]] || continue
	configured=0
	for package in "${configured_packages[@]}"; do
		[[ ${entry_package[i]} != "$package" ]] || configured=1
	done
	if ((!configured)); then
		printf 'race durations: %s is not a sharded package\n' "${entry_package[i]}" >&2
		stale=1
		continue
	fi
	in_module=0
	for package in "${sharded_packages[@]}"; do
		[[ ${entry_package[i]} != "$package" ]] || in_module=1
	done
	if ((in_module)) && [[ ${entry_test[i]} != *[*?[]* ]]; then
		printf 'race durations: %s %s matches no listed test\n' "${entry_package[i]}" "${entry_test[i]}" >&2
		stale=1
	fi
done
((!stale)) || exit 1
# Start the longest queued shard that has a free slot in its pool; a full
# CPU pool never holds back an idle lab, nor the other way round.
while ((${#queue[@]})); do
	next=
	for index in "${!queue[@]}"; do
		IFS="$tab" read -r _ name pool package expression <<< "${queue[index]}"
		if available "$pool"; then next=$index; break; fi
	done
	if [[ -z $next ]]; then finish; continue; fi
	unset 'queue[next]'
	if [[ -z $package ]]; then
		# Script contract packages invoke thousands of bounded subprocesses.
		# Under race instrumentation their aggregate can exceed Go's default
		# ten minutes.
		start "$name" "$pool" "${go[@]}" test -race -vet=off -timeout=20m "${short[@]}" -p "$package_jobs" -parallel "$test_jobs" "${other_packages[@]}"
	else
		start "$name" "$pool" "${go[@]}" test -race -vet=off -timeout=20m "${short[@]}" -parallel "$test_jobs" -run "$expression" "$package"
	fi
done

while ((${#active[@]})); do finish; done
exit "$failed"
