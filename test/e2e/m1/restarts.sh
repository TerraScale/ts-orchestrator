#!/usr/bin/env bash
source "$(dirname "$0")/setup.sh"

begin "restart ts-orch"
sudo test -s "$state/node/tls.key"
sudo test -s "$state/node/wg.key"
orch node keys >"$work/node-public-before.json"
sudo sha256sum "$state/node/tls.key" "$state/node/wg.key" | tee "$work/node-private-before.sha256" >/dev/null
whoami_pid=$(sudo fuser -n tcp 18081 2>/dev/null | xargs)
data_pid=$(sudo fuser -n tcp 18082 2>/dev/null | xargs)
test -n "$whoami_pid"
test -n "$data_pid"
sudo systemctl stop ts-orch
test "$(sudo fuser -n tcp 18081 2>/dev/null | xargs)" = "$whoami_pid"
test "$(sudo fuser -n tcp 18082 2>/dev/null | xargs)" = "$data_pid"
curl -fsS --max-time 5 http://127.0.0.1:18081/health
curl -fsS --max-time 5 http://127.0.0.1:18082/boots
sudo systemctl start ts-orch
wait_for 120 edge whoami.e2e.test /health
wait_for 60 edge data.e2e.test /boots
test "$(sudo fuser -n tcp 18081 2>/dev/null | xargs)" = "$whoami_pid"
test "$(sudo fuser -n tcp 18082 2>/dev/null | xargs)" = "$data_pid"
test "$(edge data.e2e.test /boots | wc -l)" -eq 1
test "$(edge data.e2e.test /boots | head -1)" = "$first"
orch node keys >"$work/node-public-after.json"
cmp "$work/node-public-before.json" "$work/node-public-after.json"
sudo sha256sum --check "$work/node-private-before.sha256"
test "$(sudo stat -c %a "$state/node/tls.key")" = 600
test "$(sudo stat -c %a "$state/node/wg.key")" = 600
end "ts-orch restart -> same processes serve throughout; node keys kept"

begin "restart the e2e-data task"
before=$(edge data.e2e.test /boots | wc -l)
sudo fuser -k -n tcp 18082
wait_for 120 bash -c "test \$(curl -fsS --max-time 5 --cacert $work/ca.pem --resolve data.e2e.test:443:127.0.0.1 https://data.e2e.test/boots | wc -l) -gt $before"
test "$(edge data.e2e.test /boots | head -1)" = "$first" || { echo "bind-mount data lost across restarts" >&2; exit 1; }
end "task kill -> restarted, data kept"

begin "quick task continuity across agent restart"
image=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["image"])' "$here/data.json")
sudo ctr --namespace terrascale images export "$work/busybox.tar" "$image"
sudo unshare --mount --net bash "$here/lifecycle/run.sh" "$work/readiness" "$(dirname "$bin")/lifecycle" "$image" "$work/busybox.tar" "$(dirname "$bin")/server" quick
end "same service processes, unchanged keys, retained data"
