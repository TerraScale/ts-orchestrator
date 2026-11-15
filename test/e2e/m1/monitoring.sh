#!/usr/bin/env bash
monitoring_source=$(cd "$(dirname "$0")/../../.." && pwd)
monitoring_tools=$(mktemp -d)
nice -n 19 bash "$monitoring_source/deploy/observability/production/install.sh" --check "$monitoring_tools" >"$monitoring_tools/check.log" 2>&1 &
monitoring_check=$!
source "$(dirname "$0")/setup.sh"
if ! wait "$monitoring_check"; then cat "$monitoring_tools/check.log"; exit 1; fi
cat "$monitoring_tools/check.log"

begin "task monitoring preserves service identity"
python3 "$here/monitoring/policy.py"
previous=$(mktemp -d)
git -C "$repo" fetch --quiet --depth 1 origin main
git -C "$repo" archive FETCH_HEAD deploy/observability test/e2e/m1/monitoring/rules.yml | tar -x -C "$previous"
sudo nice -n 19 unshare --mount bash "$here/monitoring/remove.sh" "$repo/deploy/observability/production/install.sh" "$previous/deploy/observability/production/install.sh" "$bin" >"$monitoring_tools/remove.log" 2>&1 &
monitoring_remove=$!
sudo swapoff --all
bash "$here/monitoring/fleet.sh" "$work" "$monitoring_tools"
if ! wait "$monitoring_remove"; then cat "$monitoring_tools/remove.log"; exit 1; fi
cat "$monitoring_tools/remove.log"
sudo "$(dirname "$bin")/monitoring" "$here/whoami.json"
end "same image -> only the recorded dashboard service is published, including after restart and adoption"
