#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$here/runtime.sh"
cache_pins
restore_runtime
sudo swapoff --all
lane="$(dirname "$bin")/single-host-region"
begin "real single-host in Oracle mode: three regions of one manager and one worker"
"$lane" fetch "$here/whoami.json" "$here/images.json" "$work/registry"
sudo --preserve-env=PATH unshare --mount --net --propagation private "$lane" "$bin" "$work/fleet" "$here/whoami.json" "$work/registry"
end "single-host-region -> every host ready on the shipped node list as on main, then on the release that embeds the list every worker edge balances, every restart ready"
