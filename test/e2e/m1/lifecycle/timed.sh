#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/../../../.." && pwd)
work=$(mktemp -d)
cleanup() { sudo python3 -c 'import shutil,sys; shutil.rmtree(sys.argv[1])' "$work"; }
trap cleanup EXIT
CGO_ENABLED=0 nice -n 19 go -C "$repo" build -trimpath -o "$work/lifecycle" ./test/e2e/m1/lifecycle
CGO_ENABLED=0 nice -n 19 go -C "$repo" build -trimpath -o "$work/readiness-server" ./test/e2e/m1/lifecycle/server
pins=$repo/deploy/m1/host-runtime.sh
containerd_version=$(sed -n 's/^containerd_version=//p' "$pins")
runc_version=$(sed -n 's/^runc_version=//p' "$pins")
case $(uname -m) in
	aarch64) arch=arm64; pin=aarch64 ;;
	x86_64) arch=amd64; pin=x86_64 ;;
	*) exit 1 ;;
esac
containerd_sha=$(sed -n "/^$pin)/,/;;/s/^\tcontainerd_sha256=//p" "$pins")
runc_sha=$(sed -n "/^$pin)/,/;;/s/^\trunc_sha256=//p" "$pins")
curl -fsSL "https://github.com/containerd/containerd/releases/download/v$containerd_version/containerd-$containerd_version-linux-$arch.tar.gz" -o "$work/containerd.tar.gz"
curl -fsSL "https://github.com/opencontainers/runc/releases/download/v$runc_version/runc.$arch" -o "$work/runc"
echo "$containerd_sha  $work/containerd.tar.gz" | sha256sum -c
echo "$runc_sha  $work/runc" | sha256sum -c
tar -C "$work" -xzf "$work/containerd.tar.gz"
install -m 0755 "$work/runc" "$work/bin/runc"
export PATH="$work/bin:$PATH"
image=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["image"])' "$repo/test/e2e/m1/data.json")
mkdir -p "$work/image"
sudo env "PATH=$PATH" nice -n 19 containerd --log-level error --root "$work/image/content" --state "$work/image/runtime" --address "$work/image/containerd.sock" &
daemon=$!
trap 'sudo kill "$daemon" 2>/dev/null || true; wait "$daemon" || true; cleanup' EXIT
sudo "$work/lifecycle" runtime "$work/image/containerd.sock"
sudo env "PATH=$PATH" ctr --address "$work/image/containerd.sock" --namespace terrascale images pull "$image"
sudo env "PATH=$PATH" ctr --address "$work/image/containerd.sock" --namespace terrascale images export "$work/busybox.tar" "$image"
sudo kill "$daemon"
wait "$daemon" || true
trap cleanup EXIT
sudo env "PATH=$PATH" nice -n 19 unshare --mount --net bash "$repo/test/e2e/m1/lifecycle/run.sh" "$work/readiness" "$work/lifecycle" "$image" "$work/busybox.tar" "$work/readiness-server"
