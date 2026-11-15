#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../../.." && pwd)
mode=$1
work=$2
python3 - "$repo" "$work" <<'PY'
import json
import sys
from pathlib import Path
repo, work = map(Path, sys.argv[1:])
(work / "overlay.json").write_text(json.dumps({"Replace": {
    str(repo / "internal/natscell/mesh/monitoring_journey.go"): str(repo / "test/e2e/m1/monitoring/_journey/metrics.go"),
    str(repo / "internal/alertdelivery/endpoints.go"): str(repo / "test/e2e/m1/monitoring/_journey/endpoints.go"),
}}))
PY
if [[ $mode == build ]]; then
  go -C "$repo" build -overlay "$work/overlay.json" -o "$work/metrics" ./test/e2e/m1/monitoring/_fleet
  go -C "$repo" build -overlay "$work/overlay.json" -o "$work/relay" ./test/e2e/m1/monitoring/_relay
  exit
fi
tools=$3
cp "$tools/metrics" "$tools/relay" "$work/"
sudo unshare --mount --net bash -s "$here/fleet.py" "$work" "$tools" <<'SH'
set -euo pipefail
mount --make-rprivate /
ip link set lo up
scratch=$(mktemp -d)
cp /etc/passwd /etc/group "$scratch/"
if ! getent passwd ts-alerts >/dev/null; then
  printf 'ts-alerts:x:32123:32123:Alert relay:/nonexistent:/usr/sbin/nologin\n' >> "$scratch/passwd"
  printf 'ts-alerts:x:32123:\n' >> "$scratch/group"
fi
mount --bind "$scratch/passwd" /etc/passwd
mount --bind "$scratch/group" /etc/group
mkdir -p /run/ts-alert-delivery
mount -t tmpfs -o mode=0750 tmpfs /run/ts-alert-delivery
exec python3 "$@"
SH
