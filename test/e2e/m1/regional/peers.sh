set -euo pipefail
repo=$(cd "$(dirname "$0")/../../../.." && pwd)
work=$1
inputs=$(python3 "$repo/test/e2e/m1/runtime-inputs.py")
eval "$inputs"
version=$containerd_version
sha=$containerd_sha256
archive=$HOME/.cache/ts-m1-runtime/containerd-$version-linux-$arch.tar.gz
if [[ ! -e $archive ]]; then
	archive=$work/containerd.tar.gz
	curl -fsSL "https://github.com/containerd/containerd/releases/download/v$version/containerd-$version-linux-$arch.tar.gz" -o "$archive"
fi
echo "$sha  $archive" | sha256sum -c --quiet
mkdir -p "$work/peers-runtime"
tar -C "$work/peers-runtime" -xzf "$archive" bin/containerd
export PATH="$work/peers-runtime/bin:$PATH"
python3 - "$repo" "$work" <<'PY'
import json
import pathlib
import sys
repo, work = map(pathlib.Path, sys.argv[1:])
source = repo / "test/e2e/m1/regional/_journey"
replace = {
    str(repo / "internal/app/release_health_journey.go"): str(source / "health.go"),
    str(repo / "internal/natscell/mesh/regional_journey.go"): str(source / "mesh.go"),
    str(repo / "internal/natscell/mesh/meta_journey.go"): str(source / "meta.go"),
    str(repo / "internal/edge/fleet_journey.go"): str(source / "fleet.go"),
    str(repo / "test/e2e/m1/regional/main.go"): str(source / "main.go"),
}
(work / "peers-overlay.json").write_text(json.dumps({"Replace": replace}))
PY
go -C "$repo" build -trimpath -overlay "$work/peers-overlay.json" -o "$work/regional-peers" ./test/e2e/m1/regional
sudo env "PATH=$PATH" "SSL_CERT_FILE=${SSL_CERT_FILE:-}" unshare -n sh -c 'ip link set lo up && exec "$0" "$@"' "$work/regional-peers" "${@:2}" "$work"
if [[ $# == 1 ]]; then
    python3 - "$repo" "$work" <<'PYTHON'
import json
import pathlib
import sys
repo, work = map(pathlib.Path, sys.argv[1:])
catalog = repo / "internal/ociregion/catalog/catalog.go"
content = catalog.read_text().replace("const foundedCount = 3", "const foundedCount = 1")
content = content.replace("var rollout = [foundedCount]string{GRU, FRA, SJC}", "var rollout = [...]string{GRU}")
target = work / "single-region-catalog.go"
target.write_text(content)
overlay = json.loads((work / "peers-overlay.json").read_text())
overlay["Replace"][str(catalog)] = str(target)
(work / "single-region-overlay.json").write_text(json.dumps(overlay))
PYTHON
    go -C "$repo" build -trimpath -overlay "$work/single-region-overlay.json" -o "$work/single-region-peers" ./test/e2e/m1/regional
    sudo env "PATH=$PATH" unshare -n sh -c 'ip link set lo up && exec "$0" "$@"' "$work/single-region-peers" single-region "$work"
fi
