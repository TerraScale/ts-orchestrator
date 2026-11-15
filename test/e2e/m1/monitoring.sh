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
bash "$here/monitoring/fleet.sh" "$work" "$monitoring_tools"
sudo swapoff --all
sudo nice -n 19 unshare --mount --net --fork bash "$here/monitoring/relay.sh" "$bin" "$monitoring_tools/rendered"
sudo "$(dirname "$bin")/monitoring" "$here/whoami.json"
end "same image -> only the recorded dashboard service is published, including after restart and adoption"
