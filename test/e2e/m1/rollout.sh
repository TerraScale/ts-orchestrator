#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$here/runtime.sh"
cache_pins
restore_runtime
begin "regional rollout bake, holds and signed replacement"
nice -n 19 bash "$here/rollout/run.sh" "$bin"
end "rollout -> later regions admit only a baked generation, holds clear only by a newer signed release"
