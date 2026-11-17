#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$here/runtime.sh"
cache_pins
restore_runtime
sudo swapoff --all
lane="$(dirname "$bin")/release-probation"
begin "a release confirms only once its node serves its region"
sudo --preserve-env=PATH unshare --mount --net --propagation private "$lane" "$bin" "$work/probation"
end "release-probation -> confirmed after mesh and release subscriptions; READY=1 without a mesh rolls back at the probation expiry"
