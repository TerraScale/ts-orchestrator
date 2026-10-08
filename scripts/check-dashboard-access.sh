#!/usr/bin/env bash
# Run only from delta, beta or mariogk-dev with NetBird already connected.
# Build ts-orch first; TS_ORCH and NB may select the binary and local client.
set -euo pipefail
case "$(hostname -s)" in
  delta|beta|mariogk-dev) ;;
  *) echo 'Dashboard checks are permitted only on delta, beta or mariogk-dev.' >&2; exit 2 ;;
esac
cd "$(dirname "$0")/.."
exec "${TS_ORCH:-dist/ts-orch}" dashboard check --netbird "${NB:-netbird}" "$@"
