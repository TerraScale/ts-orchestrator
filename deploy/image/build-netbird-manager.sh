#!/usr/bin/env bash
# Build only the dedicated GRU ARM64 manager image from retained pinned inputs.
set -euo pipefail
repository_root=$(cd -- "$(dirname -- "$(realpath -- "$0")")/../.." && pwd)
cd "$repository_root"
exec "${TS_ORCH_BIN:-ts-orch}" image build-netbird-manager "$@"
