#!/usr/bin/env bash
# Run every race-enabled Go test as one queue of shards, longest first.
#
# Listing first warms each test binary's Go build cache before any shards
# compete to build it. TS_RACE_DURATIONS (default: race-durations.txt beside
# this script) estimates what each test costs under the race detector. The
# tests of the slowest packages are packed by that cost into at most
# TS_RACE_SHARDS shards per package, longest test first into the least
# loaded shard; tests marked solo or idle get a shard of their own. Tests
# marked norace are packed the same way into CPU shards that run without
# the race detector: single-goroutine suites whose code paths start no
# goroutine, where instrumentation costs about twelve times the CPU and can
# find nothing. Every
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
#
# Packages that are not sharded run as one group per CI machine, packed by
# their "<package> - <seconds>" estimates. TS_CI_SHARD=<index>/<count> runs
# only this machine's part of the queue: every machine plans the same queue
# and takes the shards that longest-first packing gives it, so a test always
# lands on the same machine and its cached result stays valid.
#
# TS_CHANGE_BASE names the revision this change starts from. A shard whose
# failed tests all lie in packages the change does not touch re-runs those
# tests once, uncached; when they pass it prints "race flaky <package>
# <tests>" and counts as passed. Without it no failure is retried.
set -euo pipefail
# wait -n -p needs bash 5.1; older shells would fail mid-suite with an
# unbound variable instead of this message.
((BASH_VERSINFO[0] > 5 || BASH_VERSINFO[0] == 5 && BASH_VERSINFO[1] >= 1)) \
	|| { echo "race-test.sh needs bash >= 5.1 (wait -n -p), not $BASH_VERSION" >&2; exit 2; }

# GO may be a command with arguments, such as "mise exec -- go".
read -r -a go <<< "${GO:-go}"
shards=${TS_RACE_SHARDS:-6}
# Uninstrumented tests are cheap; fewer shards avoid extra test binaries.
norace_shards=${TS_RACE_NORACE_SHARDS:-2}
jobs=${TS_RACE_JOBS:-6}
idle_jobs=${TS_RACE_IDLE_JOBS:-5}
package_jobs=${TS_RACE_PACKAGE_JOBS:-4}
test_jobs=${TS_RACE_TEST_JOBS:-2}
tier=${TS_TEST_TIER:-full}
ci_shard=${TS_CI_SHARD:-1/1}
change_base=${TS_CHANGE_BASE:-}
durations=${TS_RACE_DURATIONS:-$(dirname -- "$(realpath -- "$0")")/race-durations.txt}
# The image contract suite drives the offline builder through hundreds of
# command fakes per test; unsharded it serialised most of the CI job.
sharded_packages=(./internal/app ./internal/bootstrapstart ./internal/natscell ./internal/swarmruntime ./tests/deploy)
configured_packages=("${sharded_packages[@]}")
# Shard, listing and log names use the package's last element.
declare -A seen_base=()
for package in "${sharded_packages[@]}"; do
	[[ -z ${seen_base[${package##*/}]:-} ]] || { echo "sharded packages share the name ${package##*/}: $package" >&2; exit 2; }
	seen_base[${package##*/}]=1
done
[[ $shards =~ ^[1-9][0-9]*$ ]] || { echo 'TS_RACE_SHARDS must be a positive integer' >&2; exit 2; }
[[ $norace_shards =~ ^[1-9][0-9]*$ ]] || { echo 'TS_RACE_NORACE_SHARDS must be a positive integer' >&2; exit 2; }
[[ $jobs =~ ^[1-9][0-9]*$ ]] || { echo 'TS_RACE_JOBS must be a positive integer' >&2; exit 2; }
[[ $idle_jobs =~ ^[1-9][0-9]*$ ]] || { echo 'TS_RACE_IDLE_JOBS must be a positive integer' >&2; exit 2; }
[[ $package_jobs =~ ^[1-9][0-9]*$ ]] || { echo 'TS_RACE_PACKAGE_JOBS must be a positive integer' >&2; exit 2; }
[[ $test_jobs =~ ^[1-9][0-9]*$ ]] || { echo 'TS_RACE_TEST_JOBS must be a positive integer' >&2; exit 2; }
case $tier in
	pr) short=(-short) ;;
	full) short=() ;;
	*) echo 'TS_TEST_TIER must be pr or full' >&2; exit 2 ;;
esac
if [[ $ci_shard =~ ^([1-9][0-9]*)/([1-9][0-9]*)$ ]] && ((BASH_REMATCH[1] <= BASH_REMATCH[2])); then
	machine=${BASH_REMATCH[1]} machines=${BASH_REMATCH[2]}
else
	echo 'TS_CI_SHARD must be <index>/<count> with 1 <= index <= count' >&2
	exit 2
fi
[[ -f $durations && -r $durations ]] || { echo "race durations file is not readable: $durations" >&2; exit 2; }

# Every test binary and re-executed child skips the race runtime's default
# one-second exit sleep; the tests themselves wait for their goroutines.
export GORACE="${GORACE:+$GORACE }atexit_sleep_ms=0"

# Each line: <package> <test or glob> <seconds>[/<seconds under -short>]
# [cpu|solo|idle|norace], "<package> - <seconds>" for a package that is not
# sharded, or "rest - <seconds>" for each such package without its own line.
# The first matching line wins; unmatched tests cost one second.
declare -A package_cost=()
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
	[[ -n $test && $cost =~ ^(0|[1-9][0-9]*)(/(0|[1-9][0-9]*))?$ && $pool =~ ^(cpu|solo|idle|norace)$ && -z $extra ]] || {
		echo "$durations:$line_number: want <package> <test> <seconds>[/<short seconds>] [cpu|solo|idle|norace]" >&2
		exit 2
	}
	if [[ $tier == pr ]]; then cost=${cost#*/}; else cost=${cost%%/*}; fi
	if [[ $package == rest ]]; then
		rest_cost=$cost
		continue
	fi
	if [[ $test == - ]]; then
		package_cost[$package]=$cost
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
	local completed='' status rc=0 pid
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
	local name=${active[$completed]}
	if ((rc == 0)); then
		status=ok
	elif retry_flaky "$logs/$name.log" "${active_pool[$completed]}"; then
		status=flaky
	else
		status=FAIL
		failed=1
	fi
	if [[ ${active_pool[$completed]} == idle ]]; then
		running_idle=$((running_idle - 1))
	else
		running_cpu=$((running_cpu - 1))
	fi
	printf '=== race %s: %s\n' "$name" "$status"
	cat "$logs/$name.log"
	unset 'active[$completed]' 'active_pool[$completed]'
}
# retry_flaky <log> <pool>: re-run once, uncached, each failed test of a shard
# whose failures all name a test in a package this change does not touch.
# A build failure, timeout or panic outside a test names no test and is final.
retry_flaky() {
	local log=$1 pool=$2 failure package tests dir
	local -a failures race=(-race)
	[[ -n $change_base ]] || return 1
	[[ $pool != norace ]] || race=()
	# go test prints a package's output as one block: "--- FAIL: <test>" at
	# column 0 for each failed top-level test, then "FAIL<tab><package>".
	mapfile -t failures < <(awk -F '[ \t]+' '/^--- FAIL: /{t = t (t ? "|" : "") $3} /^FAIL\t/{print $2, (t ? t : "-"); t = ""}' "$log")
	((${#failures[@]})) || return 1
	for failure in "${failures[@]}"; do
		read -r package tests <<< "$failure"
		[[ $tests != - ]] || return 1
		dir=${package#"$module"}
		dir=${dir#/}
		if grep -q -x -F -e "${dir:-.}" "$logs/changed"; then return 1; fi
	done
	for failure in "${failures[@]}"; do
		read -r package tests <<< "$failure"
		printf 'race retry %s %s\n' "$package" "$tests" >> "$log"
		"${go[@]}" test "${race[@]}" -vet=off -count=1 -timeout=20m "${short[@]}" -parallel "$test_jobs" -run "^($tests)\$" "$package" >> "$log" 2>&1 || return 1
		printf 'race flaky %s %s\n' "$package" "$tests" >> "$log"
	done
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
# Directories this change touches, one per changed file. A base this clone
# lacks (a force-pushed branch) leaves every failure final.
if [[ -n $change_base ]] && ! git cat-file -e "$change_base^{commit}" 2>/dev/null; then
	change_base=
fi
if [[ -n $change_base ]]; then
	git diff --name-only "$change_base...HEAD" | sed -e 's|/[^/]*$||' -e 't' -e 's|.*|.|' | sort -u > "$logs/changed"
fi
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
# pack <package> <packed list> <shard name prefix> <pool> <shards>: longest processing
# time first, each test joins the shard with the least estimated work so
# far, or the fewest tests when estimates tie. Adds the packed tests to
# covered. Without a package the list names packages, packed into groups.
pack() {
	local package=$1 list=$2 prefix=$3 pool=$4 bins=$5 bin best cost test shard=0 expression
	local -a loads=() counts=() members=()
	for ((bin = 0; bin < bins; bin++)); do loads[bin]=0; counts[bin]=0; members[bin]=; done
	while read -r cost test; do
		best=0
		for ((bin = 1; bin < bins; bin++)); do
			if ((loads[bin] < loads[best] || (loads[bin] == loads[best] && counts[bin] < counts[best]))); then
				best=$bin
			fi
		done
		loads[best]=$((loads[best] + cost))
		counts[best]=$((counts[best] + 1))
		members[best]="${members[best]:+${members[best]}|}$test"
	done < <(LC_ALL=C sort -k1,1nr -k2,2 "$list")
	for ((bin = 0; bin < bins; bin++)); do
		[[ -n ${members[bin]} ]] || continue
		if [[ -z $package ]]; then
			printf '%s\t%s-%s\t%s\t%s\t\n' "${loads[bin]}" "$prefix" "$shard" "$pool" "${members[bin]//|/ }" >> "$logs/queue"
			shard=$((shard + 1))
			continue
		fi
		expression=$(tr '|' '\n' <<< "${members[bin]}" | LC_ALL=C sort | paste -s -d '|')
		covered=$((covered + $(tr '|' '\n' <<< "$expression" | wc -l)))
		printf '%s\t%s-%s\t%s\t%s\t^(%s)$\n' "${loads[bin]}" "$prefix" "$shard" "$pool" "$package" "$expression" >> "$logs/queue"
		shard=$((shard + 1))
	done
}
if ((${#other_packages[@]})); then
	for package in "${other_packages[@]}"; do
		local_package=./${package#"$module"/}
		[[ $package != "$module" ]] || local_package=.
		printf '%s %s\n' "${package_cost[$local_package]:-$rest_cost}" "$package"
	done > "$logs/rest"
	pack '' "$logs/rest" packages cpu "$machines"
fi
for package in "${sharded_packages[@]}"; do
	base=${package##*/}
	mapfile -t tests < <(grep -E '^(Test|Example|Fuzz)[A-Za-z0-9_]*$' "$logs/$base.list" | LC_ALL=C sort)
	((${#tests[@]} > 0)) || { echo "no tests listed in $package" >&2; exit 1; }
	: > "$logs/$base.packed"
	: > "$logs/$base.norace"
	covered=0
	for test in "${tests[@]}"; do
		estimate "$package" "$test"
		case $est_pool in
			cpu) printf '%s %s\n' "$est_cost" "$test" >> "$logs/$base.packed" ;;
			norace) printf '%s %s\n' "$est_cost" "$test" >> "$logs/$base.norace" ;;
			*)
				printf '%s\t%s-%s\t%s\t%s\t^(%s)$\n' "$est_cost" "$base" "$test" "${est_pool/solo/cpu}" "$package" "$test" >> "$logs/queue"
				covered=$((covered + 1))
				;;
		esac
	done
	pack "$package" "$logs/$base.packed" "$base" cpu "$shards"
	pack "$package" "$logs/$base.norace" "$base-norace" norace "$norace_shards"
	[[ $covered == "${#tests[@]}" ]] || { echo "shards of $package cover $covered of ${#tests[@]} tests" >&2; exit 1; }
done
mapfile -t queue < <(LC_ALL=C sort -t "$tab" -k1,1nr -k2,2 "$logs/queue")
# Longest first, each shard goes to the CI machine with the least estimated
# work so far; this machine keeps its own.
if ((machines > 1)); then
	declare -a machine_load=() kept=()
	for ((m = 0; m < machines; m++)); do machine_load[m]=0; done
	for entry in "${queue[@]}"; do
		IFS="$tab" read -r cost _ <<< "$entry"
		best=0
		for ((m = 1; m < machines; m++)); do
			if ((machine_load[m] < machine_load[best])); then best=$m; fi
		done
		machine_load[best]=$((machine_load[best] + cost))
		if ((best == machine - 1)); then kept+=("$entry"); fi
	done
	queue=("${kept[@]}")
fi
printf 'race plan tier=%s cpu_jobs=%s idle_jobs=%s shards=%s machine=%s\n' "$tier" "$jobs" "$idle_jobs" "${#queue[@]}" "$ci_shard"
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
for package in "${!package_cost[@]}"; do
	if ! grep -q -x -F -e "$module/${package#./}" "$logs/packages" || [[ " ${sharded_packages[*]} " == *" $package "* ]]; then
		printf 'race durations: %s is not an unsharded package\n' "$package" >&2
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
	if [[ -z $expression ]]; then
		read -r -a group <<< "$package"
		# Script contract packages invoke thousands of bounded subprocesses.
		# Under race instrumentation their aggregate can exceed Go's default
		# ten minutes.
		start "$name" "$pool" "${go[@]}" test -race -vet=off -timeout=20m "${short[@]}" -p "$package_jobs" -parallel "$test_jobs" "${group[@]}"
	else
		race=(-race)
		[[ $pool != norace ]] || race=()
		start "$name" "$pool" "${go[@]}" test "${race[@]}" -vet=off -timeout=20m "${short[@]}" -parallel "$test_jobs" -run "$expression" "$package"
	fi
done

while ((${#active[@]})); do finish; done
exit "$failed"
