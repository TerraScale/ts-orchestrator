#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$here/runtime.sh"
cache_pins
restore_runtime
sudo swapoff --all
lane="$(dirname "$bin")/upgrade-gate"
begin "this build installs its next release on itself from the signed channel and on a worker still on the oldest production release"
"$lane" fetch next "$bin" "$work" "${GITHUB_SHA:?}" "$here"
sudo --preserve-env=PATH unshare --mount --net --propagation private "$lane" run next "$bin" "$work" "${GITHUB_RUN_ID:?}" "$here"
end "this build -> the same tree one run later: the manager from the signed channel, a worker on the oldest production release through the format it reads"
