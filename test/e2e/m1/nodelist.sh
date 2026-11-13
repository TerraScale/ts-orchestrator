#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$here/runtime.sh"
cache_pins
restore_runtime
nice -n 19 "$(dirname "$bin")/nodelist" "$bin"
