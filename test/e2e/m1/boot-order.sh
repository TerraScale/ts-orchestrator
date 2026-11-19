#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$here/runtime.sh"
cache_pins
restore_runtime
begin "host reboot with and without local mesh management"
nice -n 19 bash "$here/boot-order/run.sh" "$(dirname "$bin")/boot-order"
end "reboot -> mesh management starts independently, peer services recover"
