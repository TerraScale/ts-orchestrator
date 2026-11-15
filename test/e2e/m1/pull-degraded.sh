#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
trap 'rm -rf "$work"' EXIT

begin "release push past a stopped worker"
nice -n 19 "$(dirname "$bin")/pull-update" "$bin" degraded
end "a stopped worker does not hold the push; the region reports degraded until the next push reaches it"
