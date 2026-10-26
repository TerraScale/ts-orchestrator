#!/usr/bin/env bash
# The Go build/module caches also cache this pinned scanner's compilation.
# Package scans include tests and local replacements; no advisory is ignored.
set -euo pipefail
cd "$(dirname -- "$0")/../.."
test "$(go env GOVERSION)" = go1.27.3
# Reuse the existing Go build cache; cached executables are verified before use.
test "$(go env GOOS GOARCH)" = $'linux\namd64'
scanner_dir="$(go env GOCACHE)/terrascale/govulncheck-v1.9.0-go1.27.3"
scanner="$scanner_dir/govulncheck"
mkdir -p "$scanner_dir"
if [[ ! -f "$scanner" ]]; then
	GOBIN="$scanner_dir" CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 GOFLAGS='' GOWORK=off GOTOOLCHAIN=local \
		go install -trimpath golang.org/x/vuln/cmd/govulncheck@v1.9.0
fi
echo "d36c5d591f43f085b4561a3a9db05894d343a86376f20fab7d8c4ffff38b7a01  $scanner" | sha256sum --check
chmod +x "$scanner"
"$scanner" -mode=binary -scan=module -show=verbose "$scanner"

case ${1:-source} in
source)
	mapfile -d '' -t manifests < <(git ls-files -z -- go.mod '**/go.mod')
	count=0
	for manifest in "${manifests[@]}"; do
		# Immutable historical evidence/snapshots do not select current builds.
		case "$manifest" in docs/evidence/*|docs/patches/*/snapshot/*) continue ;; esac
		module=$(dirname -- "$manifest")
		echo "Auditing package/test graph: $module"
		(cd "$module" && "$scanner" -scan=package -test ./...)
		count=$((count + 1))
	done
	test "$count" -gt 0
	;;
release)
	for binary in dist/terrascale-orchestrator-linux-{amd64,arm64}; do
		go version -m "$binary"
		test "$(go version "$binary" | awk '{print $NF}')" = go1.27.3
		# A stripped symbol table makes package reachability ambiguous.
		go tool nm "$binary" > /dev/null
		"$scanner" -mode=binary "$binary"
	done
	;;
*) echo 'usage: audit-dependencies.sh [source|release]' >&2; exit 2 ;;
esac
