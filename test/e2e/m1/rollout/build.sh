#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../../.." && pwd)
overlay=$(mktemp -d)
trap 'rm -rf "$overlay"' EXIT
python3 - "$repo" "$overlay" "${2:-$repo/internal/rollout/bake.go}" <<'PY'
import json
import pathlib
import sys
repo, overlay, source = map(pathlib.Path, sys.argv[1:])
original = repo / "internal/rollout/bake.go"
content = source.read_text().replace('"time"', '"time"\n laneclock "github.com/TerraScale/ts-orchestrator/test/e2e/m1/rollout/clock"')
content = content.replace("time.Now()", "laneclock.Now()").replace("time.Since(", "laneclock.Since(")
(overlay / "bake.go").write_text(content)
(overlay / "overlay.json").write_text(json.dumps({"Replace": {str(original): str(overlay / "bake.go")}}))
PY
CGO_ENABLED=0 go -C "$repo" build -trimpath -overlay "$overlay/overlay.json" -o "$1" ./test/e2e/m1/rollout
