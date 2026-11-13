set -euo pipefail
binary=$(realpath "$1")
repo=$(cd "$(dirname "$0")/../../../.." && pwd)
cd "$repo"
work=$(mktemp -d)
cleanup() {
 local result=$?
 if ((result != 0)); then sudo tail -n 25 "$work"/*.log || true; fi
 sudo rm -rf "$work"
 exit "$result"
}
trap cleanup EXIT
previous="${CERTIFICATE_PREVIOUS_REF:-8bc71eb41}"
git fetch origin "$previous"
mkdir "$work/main"
git archive FETCH_HEAD | tar -x -C "$work/main"
nice -n 19 go build -p 2 -trimpath -o "$work/certificates" ./test/e2e/m1/certificates
nice -n 19 go -C "$work/main" build -p 2 -trimpath -o "$work/main-orchestrator" ./cmd/terrascale-orchestrator
python3 - "$work" "$binary" <<'PY'
import json
import secrets
import sys
import os
work, binary = sys.argv[1:]
with open(work + "/lane.json", "w") as output:
    json.dump({"Work": work, "Binary": binary, "MainBinary": work + "/main-orchestrator", "MeshSeed": secrets.token_hex(32), "DatabaseToken": secrets.token_hex(32)}, output)
os.chmod(work + "/lane.json", 0o600)
PY
sudo env PATH="$PATH" unshare --mount --net --pid --fork --mount-proc bash -s -- "$work" <<'NS'
set -euo pipefail
mount --make-rprivate /
mount -t tmpfs tmpfs /var/lib
mount -t tmpfs tmpfs /var/log
mkdir -p /etc/netns /run/netns
mount -t tmpfs tmpfs /etc/netns
mount -t tmpfs tmpfs /run/netns
work=$1
mkdir -p "$work/containerd"
mkdir -p /run/containerd
mount --bind "$work/containerd" /run/containerd
nice -n 19 "$work/certificates" journey "$work/lane.json"
NS
