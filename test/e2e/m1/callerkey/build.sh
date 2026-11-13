set -euo pipefail
output=$(realpath -m "$1")
mkdir -p "$output"
python3 - "$PWD" "$output/overlay.json" <<'PY'
import json
import sys
from pathlib import Path
root = Path(sys.argv[1])
Path(sys.argv[2]).write_text(json.dumps({"Replace": {str(root / "internal/callerkey/vault.go"): str(root / "test/e2e/m1/callerkey/store.go.txt")}}))
PY
CGO_ENABLED=0 go build -overlay "$output/overlay.json" -trimpath -o "$output/" ./cmd/terrascale-orchestrator ./test/e2e/m1/callerkey
"$output/callerkey" list > "$output/cases.txt"
