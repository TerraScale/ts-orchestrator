#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
trap 'rm -rf "$work"' EXIT

begin "pull gate: the regional health gate against the state before the release"
nice -n 19 "$(dirname "$bin")/pull-update" "$bin" bake
end "GRU passes first; FRA can withhold a release or roll it back alone while SJC holds; GRU failure holds both later regions"
