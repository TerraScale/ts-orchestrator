#!/usr/bin/env bash
# Read-only: dual meshes on PCs/clients; NetBird on regional --node servers.
set -euo pipefail
cd "$(dirname "$0")/.."
exec "${TS_ORCH:-dist/ts-orch}" network check "$@"
