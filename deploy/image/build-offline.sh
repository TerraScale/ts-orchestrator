#!/usr/bin/env bash
# Build deployment-neutral host images through the unified native CLI.
set -euo pipefail
repository_root=$(cd -- "$(dirname -- "$(realpath -- "$0")")/../.." && pwd)
cd "$repository_root"
exec "${TS_ORCH_BIN:-ts-orch}" image build-offline "$@"
