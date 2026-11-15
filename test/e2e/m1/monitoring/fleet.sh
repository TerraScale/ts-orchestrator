#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../../.." && pwd)
work=$1
tools=$2
python3 - "$repo" "$work" <<'PY'
import json
import sys
from pathlib import Path
repo, work = map(Path, sys.argv[1:])
(work / "overlay.json").write_text(json.dumps({"Replace": {
    str(repo / "internal/natscell/mesh/monitoring_journey.go"): str(repo / "test/e2e/m1/monitoring/_journey/metrics.go"),
}}))
PY
go -C "$repo" build -overlay "$work/overlay.json" -o "$work/metrics" ./test/e2e/m1/monitoring/_fleet
sudo unshare --net bash -c 'ip link set lo up; exec python3 "$@"' bash "$here/fleet.py" "$work" "$tools"
