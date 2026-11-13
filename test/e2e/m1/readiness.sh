#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
begin "readiness reporting"
source "$here/runtime.sh"
restore_runtime
if ! $cache_hit; then
	cache_pins
	restore_runtime
fi
export PATH="$HOME/.local/bin:$PATH"
image=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["image"])' "$here/data.json")
sudo env "PATH=$PATH" unshare --mount --net --fork bash "$here/lifecycle/prepare.sh" "$work" "$(dirname "$bin")" "$image"
end "readiness reporting"
