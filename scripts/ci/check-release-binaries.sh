#!/usr/bin/env bash
# Check the static release binaries in dist/ and write dist/SHA256SUMS:
# expected ELF machine, no interpreter or shared libraries, and embedded
# clean VCS metadata for the exact source revision (SOURCE_SHA, default HEAD).
set -euo pipefail

repository_root=$(cd -- "$(dirname -- "$(realpath -- "$0")")/../.." && pwd)
cd "$repository_root"
GO=${GO:-go}
source_sha=${SOURCE_SHA:-$(git rev-parse HEAD)}
[[ $source_sha =~ ^[0-9a-f]{40}$ ]] || { echo 'SOURCE_SHA must be a full commit SHA' >&2; exit 2; }

for pair in "linux-amd64:Advanced Micro Devices X86-64" "linux-arm64:AArch64"; do
	asset=${pair%%:*}
	expected_machine=${pair#*:}
	executable="dist/terrascale-orchestrator-${asset}"
	test -s "$executable"
	machine=$(readelf -h "$executable" | awk -F: '/Machine:/ {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2}')
	[[ $machine == "$expected_machine" ]] || { echo "$executable is $machine, not $expected_machine" >&2; exit 1; }
	if readelf -l "$executable" | grep -Fq 'INTERP'; then
		echo "$executable contains a dynamic interpreter" >&2
		exit 1
	fi
	if readelf -d "$executable" 2>/dev/null | grep -Eq 'NEEDED'; then
		echo "$executable has dynamic library dependencies" >&2
		exit 1
	fi
	build_info=$($GO version -m "$executable")
	if ! grep -Fq "vcs.revision=${source_sha}" <<< "$build_info" || ! grep -Fq 'vcs.modified=false' <<< "$build_info"; then
		echo "$executable does not embed the clean source revision $source_sha" >&2
		exit 1
	fi
	printf 'verified %s machine=%s bytes=%s sha256=%s source=%s\n' \
		"$executable" "$machine" "$(stat -c '%s' "$executable")" \
		"$(sha256sum "$executable" | awk '{print $1}')" "$source_sha"
done
(cd dist && sha256sum terrascale-orchestrator-linux-amd64 terrascale-orchestrator-linux-arm64) > dist/SHA256SUMS
cat dist/SHA256SUMS
