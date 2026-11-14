set -euo pipefail
repo=$(cd "$(dirname "$0")/../../../.." && pwd)
work=$1
runtime_pins=$repo/deploy/m1/host-runtime.sh
version=$(sed -n 's/^containerd_version=//p' "$runtime_pins")
host_arch=$(uname -m)
case "$host_arch" in
aarch64) arch=arm64 ;;
x86_64) arch=amd64 ;;
*) echo "regional peers needs a pinned containerd architecture" >&2; exit 1 ;;
esac
sha=$(sed -n "/^$host_arch)/,/;;/s/^\tcontainerd_sha256=//p" "$runtime_pins")
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
    str(repo / "internal/natscell/mesh/regional_journey.go"): str(source / "mesh.go"),
    str(repo / "internal/natscell/mesh/meta_journey.go"): str(source / "meta.go"),
    str(repo / "test/e2e/m1/regional/main.go"): str(source / "main.go"),
}
(work / "peers-overlay.json").write_text(json.dumps({"Replace": replace}))
PY
go -C "$repo" build -trimpath -overlay "$work/peers-overlay.json" -o "$work/regional-peers" ./test/e2e/m1/regional
sudo env "PATH=$PATH" unshare -n sh -c 'ip link set lo up && exec "$0" "$@"' "$work/regional-peers" "$work"
