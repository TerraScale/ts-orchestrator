#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
trap 'rm -rf "$work"' EXIT

begin "pull gate: the regional health gate against the state before the release"
nice -n 19 "$(dirname "$bin")/pull-update" "$bin" bake
end "a degraded region takes a release and passes in order; a replica that never becomes ready or a restarted task rolls it back and holds the next region"
