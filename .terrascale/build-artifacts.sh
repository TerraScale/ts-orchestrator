#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ! "$1" =~ ^artifacts/[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$ ]]; then
  echo "usage: $0 artifacts/<output>" >&2
  exit 2
fi

output="$1"
current=""
IFS='/' read -r -a output_components <<<"$output"
for component in "${output_components[@]}"; do
  if [[ -z "$current" ]]; then
    current="$component"
  else
    current="$current/$component"
  fi
  if [[ -L "$current" ]]; then
    echo "refusing symlinked artifact output component: $current" >&2
    exit 2
  fi
done

rm -rf -- "$output"

expected_files=(
  linux-arm64/orchestrator-tooling
  linux-arm64/seccomp/terrascale-default-v1.json
  linux-arm64/terrascale-orchestrator
  linux-arm64/ts-node
  linux-x64/orchestrator-tooling
  linux-x64/seccomp/terrascale-default-v1.json
  linux-x64/terrascale-orchestrator
  linux-x64/ts-node
)

build_architecture() {
  local goarch="$1"
  local directory="$2"

  mkdir -p "$output/$directory/seccomp"
  CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -trimpath -o "$output/$directory/terrascale-orchestrator" ./cmd/orchestrator
  CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -trimpath -o "$output/$directory/ts-node" ./cmd/ts-node
  CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -trimpath -o "$output/$directory/orchestrator-tooling" ./tools/orchestrator-tooling
  cp .terrascale/seccomp/terrascale-default-v1.json "$output/$directory/seccomp/terrascale-default-v1.json"
}

build_architecture amd64 linux-x64
build_architecture arm64 linux-arm64

mapfile -t actual_files < <(find "$output" -type f -printf '%P\n' | LC_ALL=C sort)
expected_text=$(printf '%s\n' "${expected_files[@]}")
actual_text=$(printf '%s\n' "${actual_files[@]}")
if [[ "$actual_text" != "$expected_text" ]]; then
  echo "artifact file set mismatch" >&2
  printf 'expected:\n%s\n' "$expected_text" >&2
  printf 'actual:\n%s\n' "$actual_text" >&2
  exit 1
fi

for executable in \
  linux-arm64/orchestrator-tooling \
  linux-arm64/terrascale-orchestrator \
  linux-arm64/ts-node \
  linux-x64/orchestrator-tooling \
  linux-x64/terrascale-orchestrator \
  linux-x64/ts-node; do
  test -x "$output/$executable"
done
