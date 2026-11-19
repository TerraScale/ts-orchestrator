#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$here/runtime.sh"
restore_runtime
sudo swapoff --all
lane="$(dirname "$bin")/oracle-regions"
begin "real nodes in Oracle mode across three regions"
"$lane" fetch "$here/whoami.json" "$here/images.json" "$work/registry"
sudo --preserve-env=PATH unshare --mount --net --propagation private "$lane" "$bin" "$work/fleet" "$here/whoami.json" "$work/registry"
end "oracle-regions -> every worker serves from its manager's certificate-signed inventory with no release; forged, other-region and departed publishers refused; a promoted manager publishes"
