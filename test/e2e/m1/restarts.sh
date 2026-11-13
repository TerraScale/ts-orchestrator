#!/usr/bin/env bash
source "$(dirname "$0")/setup.sh"

begin "restart ts-orch"
sudo test -s "$state/node/tls.key"
sudo test -s "$state/node/wg.key"
orch node keys >"$work/node-public-before.json"
sudo sha256sum "$state/node/tls.key" "$state/node/wg.key" | tee "$work/node-private-before.sha256" >/dev/null
sudo systemctl restart ts-orch
wait_for 120 edge whoami.e2e.test /health
wait_for 60 edge data.e2e.test /boots
orch node keys >"$work/node-public-after.json"
cmp "$work/node-public-before.json" "$work/node-public-after.json"
sudo sha256sum --check "$work/node-private-before.sha256"
test "$(sudo stat -c %a "$state/node/tls.key")" = 600
test "$(sudo stat -c %a "$state/node/wg.key")" = 600
end "ts-orch restart -> both served, node keys kept"

begin "restart the e2e-data task"
before=$(edge data.e2e.test /boots | wc -l)
sudo fuser -k -n tcp 18082
wait_for 120 bash -c "test \$(curl -fsS --max-time 5 --cacert $work/ca.pem --resolve data.e2e.test:443:127.0.0.1 https://data.e2e.test/boots | wc -l) -gt $before"
test "$(edge data.e2e.test /boots | head -1)" = "$first" || { echo "bind-mount data lost across restarts" >&2; exit 1; }
end "task kill -> restarted, data kept"
