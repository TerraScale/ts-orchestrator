#!/usr/bin/env bash
# Run the qualification tier (T2) for this revision before image.yml builds
# its image.
#
# usage: qualify-image.sh
#
# TS_QUALIFICATION_SUITES names, separated by spaces, the suites whose
# fixtures this runner supplies; image.yml passes the repository variable of
# the same name and skips this step while it is unset. Suites and the
# environment each one requires:
#
#   terrabase-walkthrough    TS_TERRABASE_SERVER: a tb-server for this runner's
#                            architecture, built from the TerraBase revision
#                            pinned in deploy/image/image-inputs.json. The job
#                            needs a finite cgroup memory.max (tb-server
#                            requires one), unprivileged user and network
#                            namespaces and ip(8).
#   terrabase-successor      TS_D11_RUST_SERVER and/or TS_D11_PUBLIC_ARTIFACT_DIR.
#   native-validator         TS_TEST_NATIVE_VERIFIER_SHA256 and
#                            TS_TEST_NATIVE_VERIFIER_SOURCE_COMMIT.
#   rendered-sfo-enrollment  TS_TEST_RENDERED_HOST_BUNDLE,
#                            TS_TEST_RENDERED_HOST_MATERIAL and
#                            TS_TEST_RENDERED_HOST_BUNDLE_SHA256.
#   terrabase-binary         TS_TERRABASE_BINARY: a C# TerraBase release asset
#   terrabase-release        (terrabase-linux-<arch>) with its .sha256 beside it.
#   cellscale-oci-readonly   TS_CELLSCALE_OCI_REGION and
#                            TS_CELLSCALE_OCI_COMPARTMENT, with the runner's
#                            ~/.oci/config DEFAULT profile; optional
#                            TS_CELLSCALE_OCI_AD, _IMAGE and _SUBNET. Reads
#                            only: instances, image, subnet, shapes, quota.
#
# The D10 backup bridges (TestBackupGoRust*ProcessBridge) are not a suite:
# each is a child process that a TerraBase Rust parent test starts with its
# own packet and result path while it drives live members, so it cannot run
# from a static fixture here, and the operation and completion bridges
# would write the one TS_D10_PROCESS_RESULT their parents each read.
#
# TS_TEST_TIER=qualification makes a missing fixture fail its test rather
# than skip it, and a suite also fails if any selected test reports SKIP, so
# this gate cannot pass vacuously. The Firecracker suites run through
# `ts-orch qualification firecracker ...` on a KVM host, not here.
#
# All suites share one budget, TS_QUALIFICATION_BUDGET_SECONDS (default 2400,
# 40 minutes); each suite's -timeout is what remains of it. image.yml's job
# timeout reserves exactly this budget on top of the gate's wait and the
# build, so slow suites fail here instead of the runner killing the build.
set -euo pipefail

# GO may be a command with arguments, such as "mise exec -- go".
read -r -a go <<< "${GO:-go}"
# A multi-line repository variable must not silently drop every suite after
# its first line: read the whole value (read -d '' returns 1 at EOF).
read -r -d '' -a suites <<< "${TS_QUALIFICATION_SUITES:-}" || true
budget=${TS_QUALIFICATION_BUDGET_SECONDS:-2400}
[[ $budget =~ ^[1-9][0-9]*$ ]] || { echo "TS_QUALIFICATION_BUDGET_SECONDS must be a positive number of seconds: $budget" >&2; exit 2; }
((${#suites[@]})) || { echo 'TS_QUALIFICATION_SUITES names no qualification suite' >&2; exit 2; }
declare -A packages=(
	[terrabase-walkthrough]=./internal/app
	[terrabase-successor]=./internal/managedmaterial
	[native-validator]=./internal/managedmaterial
	[rendered-sfo-enrollment]=./internal/app
	[terrabase-binary]=./internal/terrabase
	[terrabase-release]=./internal/app
	[cellscale-oci-readonly]=./internal/cellscale
)
declare -A tests=(
	[terrabase-walkthrough]='^TestTerraBaseWalkthroughAgainstRealMembers$'
	[terrabase-successor]='^TestProduceSuccessorRustInterop$'
	[native-validator]='^TestPrepareInitialUsesAdmittedPackagedNativeValidator$'
	[rendered-sfo-enrollment]='^TestManagedPlacementEnrollmentFromRenderedSFOBundle$'
	[terrabase-binary]='^TestTerraBaseBinaryPeerMesh$'
	[terrabase-release]='^TestTerraBaseReleaseDeployUpgradeRollback$'
	[cellscale-oci-readonly]='^TestOCIReadOnlyAgainstRealAPI$'
)
for suite in "${suites[@]}"; do
	[[ -n ${packages[$suite]:-} ]] || { echo "unknown qualification suite: $suite" >&2; exit 2; }
done

export TS_TEST_TIER=qualification
logs=$(mktemp -d "${TMPDIR:-/tmp}/qualify-image.XXXXXXXX")
trap 'rm -rf -- "$logs"' EXIT
failed=0
deadline=$((SECONDS + budget))
for suite in "${suites[@]}"; do
	remaining=$((deadline - SECONDS))
	if ((remaining <= 0)); then
		echo "qualification suite $suite did not run: the ${budget}s qualification budget is spent" >&2
		failed=1
		continue
	fi
	status=0
	"${go[@]}" test -count=1 -v -timeout="${remaining}s" -run "${tests[$suite]}" "${packages[$suite]}" > "$logs/$suite.log" 2>&1 || status=$?
	cat "$logs/$suite.log"
	if ((status != 0)); then
		echo "qualification suite $suite failed" >&2
		failed=1
	elif grep -q -E '^[[:space:]]*--- SKIP: ' "$logs/$suite.log"; then
		echo "qualification suite $suite skipped a test; its fixture is incomplete" >&2
		failed=1
	elif ! grep -q -E '^--- PASS: ' "$logs/$suite.log"; then
		echo "qualification suite $suite ran no test" >&2
		failed=1
	else
		echo "qualification suite $suite passed"
	fi
done
exit "$failed"
