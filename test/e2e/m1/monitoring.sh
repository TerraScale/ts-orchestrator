#!/usr/bin/env bash
monitoring_source=$(cd "$(dirname "$0")/../../.." && pwd)
monitoring_tools=$(mktemp -d)
nice -n 19 bash "$monitoring_source/deploy/observability/production/install.sh" --check "$monitoring_tools" >"$monitoring_tools/check.log" 2>&1 &
monitoring_check=$!
nice -n 19 bash "$monitoring_source/test/e2e/m1/monitoring/fleet.sh" build "$monitoring_tools" >"$monitoring_tools/build.log" 2>&1 &
monitoring_build=$!
source "$(dirname "$0")/setup.sh"
if ! wait "$monitoring_check"; then cat "$monitoring_tools/check.log"; exit 1; fi
cat "$monitoring_tools/check.log"

begin "task monitoring preserves service identity"
python3 "$here/monitoring/policy.py"
previous=$(mktemp -d)
if [[ -n ${CHANGE_BASE:-} && ${CHANGE_BASE:-} != 0000000000000000000000000000000000000000 ]]; then
 previous_ref=$CHANGE_BASE
else
 previous_ref=main
fi
git -C "$repo" fetch --quiet --depth 1 origin "$previous_ref"
git -C "$repo" archive FETCH_HEAD deploy/observability test/e2e/m1/monitoring/rules.yml | tar -x -C "$previous"
sudo nice -n 19 unshare --mount bash "$here/monitoring/remove.sh" "$repo/deploy/observability/production/install.sh" "$previous/deploy/observability/production/install.sh" "$bin" >"$monitoring_tools/remove.log" 2>&1 &
monitoring_remove=$!
sudo swapoff --all
if ! wait "$monitoring_build"; then cat "$monitoring_tools/build.log"; exit 1; fi
bash "$here/monitoring/fleet.sh" run "$work" "$monitoring_tools"
if ! wait "$monitoring_remove"; then cat "$monitoring_tools/remove.log"; exit 1; fi
cat "$monitoring_tools/remove.log"
sudo "$(dirname "$bin")/monitoring" "$here/whoami.json"
end "same image -> only the recorded dashboard service is published, including after restart and adoption"
