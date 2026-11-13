#!/usr/bin/env bash
set -euo pipefail
bin=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
echo "rollout lane work: $work"
started=$SECONDS
bash "$here/build.sh" "$work/rollout-journey"
python3 - "$here/../whoami.json" "$here/../images.json" "$work/spec.json" <<'PY'
import json
import platform
import sys
spec = json.load(open(sys.argv[1]))
arch = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
spec["image"] = json.load(open(sys.argv[2]))["e2e-whoami"][arch]
with open(sys.argv[3], "w") as output:
    json.dump(spec, output)
PY
"$work/rollout-journey" clocks "$work/clocks"
privilege=()
if ((EUID != 0)); then
 privilege=(sudo --preserve-env=PATH)
fi
"${privilege[@]}" bash "$here/fleet.sh" "$work/rollout-journey" "$work/fleet" "$work/spec.json" "$bin"
echo "rollout lane measured: $((SECONDS - started)) seconds"
