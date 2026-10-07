#!/usr/bin/env bash
# Run from the laptop, delta, beta and mariogk-dev with NetBird connected.
# Build ts-orch first; TS_ORCH and NB may select the binary and local client.
set -euo pipefail
cd "$(dirname "$0")/.."
exec "${TS_ORCH:-dist/ts-orch}" dashboard check --netbird "${NB:-netbird}" "$@"
