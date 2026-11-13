#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$here/runtime.sh"
cache_pins
restore_runtime
begin "regional installation bake and interruption budgets"
nice -n 19 bash "$here/rollout/run.sh" "$bin" install
end "first and added regions bake; unsaved failures and interrupted windows remain visible"
