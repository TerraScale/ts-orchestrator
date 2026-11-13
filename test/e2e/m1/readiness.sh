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
tools=$(mktemp -d /tmp/readiness-tools.XXXXXX)
chmod 0755 "$tools"
install -m 0755 "$(dirname "$bin")/lifecycle" "$(dirname "$bin")/server" "$tools/"
sudo env "PATH=$PATH" unshare --mount --fork bash "$here/lifecycle/prepare.sh" "$work" "$tools" "$image"
sudo env "PATH=$PATH" unshare --mount --net --fork bash "$here/lifecycle/run.sh" "$work/readiness" "$tools/lifecycle" "$image" "$work/busybox.tar" "$tools/server"
end "readiness reporting"
