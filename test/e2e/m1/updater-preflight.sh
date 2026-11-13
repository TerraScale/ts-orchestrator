#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"

begin "release preflight, commit point, refusals and probation"
bash "$here/updater-preflight/run.sh" "$bin"
end "release -> candidate preflight before the swap, one commit point, integrity failures stop the rollout"

begin "alert relay runtime files"
sudo swapoff --all
bash "$here/alert-prepare/run.sh"
end "prepare -> root-owned files on tmpfs with swap off, other filesystems refused"
