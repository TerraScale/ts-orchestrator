#!/usr/bin/env bash
# Fail when a tracked file mentions Fly.io: TerraScale runs only on OCI
# (user order 2026-10-22). Tigris object storage reached through Fly stays
# (user Q-TIGRIS 2026-10-22), so its endpoint and "fly storage" commands pass.
# third_party is upstream code, where "on the fly" is plain English.
set -euo pipefail

found=$(git grep -n -I -i -E 'fly\.io|flyctl|fly\.dev|\bfly\b|flyio|FLY_' -- . ':!third_party' ':!scripts/ci/retired-host-check.sh' |
	grep -v -i -E 'fly\.storage\.tigris\.dev|fly storage' || true)
if [[ -n $found ]]; then
	printf '%s\n' "$found"
	echo 'retired-host-check: remove the Fly.io mentions above; everything runs on OCI (Tigris storage lines excepted).' >&2
	exit 1
fi
