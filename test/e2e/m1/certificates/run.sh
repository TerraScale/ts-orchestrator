set -euo pipefail
binary=$(realpath "$1")
repo=$(cd "$(dirname "$0")/../../../.." && pwd)
cd "$repo"
work=$(mktemp -d)
cleanup() {
 result=$?
 if ((result != 0)); then sudo tail -n 30 "$work"/*.log || true; fi
 sudo rm -rf "$work"
 exit "$result"
}
trap cleanup EXIT
base=$(git merge-base HEAD "${CHANGE_BASE:-origin/main}")
mkdir "$work/main"
git archive "$base" | tar -x -C "$work/main"
mkdir -p "$work/main/test/e2e/m1/certificates/previous"
cp test/e2e/m1/certificates/previous/main.go "$work/main/test/e2e/m1/certificates/previous/"
go -C "$work/main" build -trimpath -o "$work/previous-edge" ./test/e2e/m1/certificates/previous
cp "$(dirname "$binary")/certificates" "$work/certificates"
cp "$binary" "$work/ts-orch"
python3 - "$work" <<'PY'
import json
import sys
from pathlib import Path
work = Path(sys.argv[1])
(work / "lane.json").write_text(json.dumps({"Work": str(work)}))
PY
sudo env PATH="$PATH" unshare --mount --net --pid --fork --mount-proc bash -s -- "$work" <<'NS'
set -euo pipefail
mount --make-rprivate /
mount -t tmpfs tmpfs /var/lib
mkdir -p /etc/netns /run/netns
mount -t tmpfs tmpfs /etc/netns
mount -t tmpfs tmpfs /run/netns
exec "$1/certificates" journey "$1/lane.json"
NS
