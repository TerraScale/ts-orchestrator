#!/usr/bin/env bash
set -euo pipefail
out=$(realpath -m "$1")
repo=$(cd "$(dirname "$0")/../../.." && pwd)
mkdir -p "$out"
start=$(date +%s)
CGO_ENABLED=0 go -C "$repo" build -trimpath -o "$out/" ./cmd/terrascale-orchestrator ./test/e2e/m1/...
echo "shared build: $(($(date +%s) - start)) s"
