#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$here/runtime.sh"
cache_pins
restore_runtime
sudo swapoff --all
lane="$(dirname "$bin")/upgrade-gate"
begin "the released updater installs this build"
"$lane" fetch previous "$bin" "$work" "${GITHUB_SHA:?}" "$here"
sudo --preserve-env=PATH unshare --mount --net --propagation private "$lane" run previous "$bin" "$work" "${GITHUB_RUN_ID:?}" "$here"
end "pinned release -> this build on both hosts through its own discovery, lineage, provenance, preflight and probation"
