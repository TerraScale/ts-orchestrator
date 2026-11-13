set -euo pipefail
bin=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
python=$(python3 -c 'import sys; print(sys.executable)')
trap 'sudo rm -rf "$work"' EXIT
nice -n 19 go build -o "$work/seed" "$here/startup"
nice -n 19 go run -p 1 "$here/updater-preflight" "$bin"
bash "$here/alert-prepare/run.sh"
version=$(sed -n 's/^containerd_version=//p' "$here/../../../deploy/m1/host-runtime.sh")
arch=$(uname -m)
case $arch in
	x86_64) arch=amd64 ;;
	aarch64) arch=arm64 ;;
esac
curl -fsSL "https://github.com/containerd/containerd/releases/download/v$version/containerd-$version-linux-$arch.tar.gz" -o "$work/containerd.tar.gz"
tar -C "$work" -xzf "$work/containerd.tar.gz" bin/containerd
sudo unshare --mount --net bash -s -- "$bin" "$here" "$work" "$python" <<'SH_INNER'
set -euo pipefail
bin=$1
here=$2
work=$3
python=$4
mount --make-rprivate /
mkdir -p "$work/runtime" /run/containerd
mount --bind "$work/runtime" /run/containerd
nice -n 19 "$python" "$here/startup.py" "$bin" "$work/seed" "$work"
SH_INNER
