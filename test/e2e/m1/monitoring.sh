#!/usr/bin/env bash
source "$(dirname "$0")/setup.sh"

begin "task monitoring preserves service identity"
nice -n 19 python3 "$here/monitoring/host_sets.py"
nice -n 19 bash "$repo/deploy/observability/production/install.sh" --check
sudo nice -n 19 unshare --mount --net --fork bash "$here/monitoring/relay.sh" "$bin"
sudo "$(dirname "$bin")/monitoring" "$here/whoami.json"
end "same image -> only the recorded dashboard service is published, including after restart and adoption"
