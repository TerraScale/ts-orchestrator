#!/usr/bin/env sh
# Compatibility entrypoint; the single Go binary owns installation and bootstrap.
set -eu
exec /usr/local/bin/ts-orch netbird foundation install "$@"
