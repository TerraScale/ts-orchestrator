#!/usr/bin/env bash
source "$(dirname "$0")/setup.sh"

begin "restart ts-orch: withdraw, serve through propagation, drain, normal exit under 30 seconds"
identity=$state/swarm/certificates
sudo test -s "$identity/swarm-node.key"
sudo sha256sum "$identity/swarm-node.key" "$identity/swarm-node.crt" | tee "$work/node-identity-before.sha256" >/dev/null
whoami_pid=$(sudo fuser -n tcp 18081 2>/dev/null | xargs)
data_pid=$(sudo fuser -n tcp 18082 2>/dev/null | xargs)
test -n "$whoami_pid"
test -n "$data_pid"
python3 "$here/stop-stream.py" "$work/ca.pem" "$data"
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
sudo sha256sum --check "$work/node-identity-before.sha256"
test "$(sudo stat -c %a "$identity/swarm-node.key")" = 600
end "ts-orch restart -> effective withdrawal window kept; application responses complete; same processes and SwarmKit identity kept"

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
