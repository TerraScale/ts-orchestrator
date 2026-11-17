#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
trap 'rm -rf "$work"' EXIT

begin "pull rollout waits for an unavailable worker"
nice -n 19 "$(dirname "$bin")/pull-update" "$bin" degraded
end "an unavailable worker blocks the first region and every later region until it returns"
