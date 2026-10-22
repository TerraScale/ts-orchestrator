#!/usr/bin/env bash
# Fail when a tracked file mentions Fly.io: TerraScale runs only on OCI
# (user order 2026-10-22). third_party is upstream code, where "on the fly"
# is plain English.
set -euo pipefail

if git grep -n -I -i -E 'fly\.io|flyctl|fly\.dev|\bfly\b|flyio|FLY_' -- . ':!third_party' ':!scripts/ci/retired-host-check.sh'; then
	echo 'retired-host-check: remove the Fly.io mentions above; everything runs on OCI.' >&2
	exit 1
fi
