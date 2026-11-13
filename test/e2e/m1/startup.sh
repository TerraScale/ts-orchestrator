set -euo pipefail
bin=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
python=$(python3 -c 'import sys; print(sys.executable)')
trap 'sudo rm -rf "$work"' EXIT
nice -n 19 go build -o "$work/seed" "$here/startup"
nice -n 19 go build -o "$work/host-credentials" "$here/host-credentials"
version=$(sed -n 's/^containerd_version=//p' "$here/../../../deploy/m1/host-runtime.sh")
arch=$(uname -m)
case $arch in
	x86_64) arch=amd64 ;;
	aarch64) arch=arm64 ;;
esac
curl -fsSL "https://github.com/containerd/containerd/releases/download/v$version/containerd-$version-linux-$arch.tar.gz" -o "$work/containerd.tar.gz"
tar -C "$work" -xzf "$work/containerd.tar.gz" bin/containerd
sudo unshare --mount --net bash -s -- "$bin" "$work" <<'SH_CREDENTIALS'
set -euo pipefail
bin=$1
work=$2
mount --make-rprivate /
ip link set lo up
"$work/host-credentials" "$bin" "$work"
SH_CREDENTIALS
mkdir -p "$work/preflight-sys/class/dmi/id"
printf 'OracleCloud.com\n' > "$work/preflight-sys/class/dmi/id/chassis_asset_tag"
sudo unshare --mount --net bash -s -- "$bin" "$work" <<'SH_PREFLIGHT'
set -euo pipefail
bin=$1
work=$2
mount --make-rprivate /
mount --bind "$work/preflight-sys" /sys
if "$bin" vault check-services > "$work/preflight-output" 2>&1; then
	cat "$work/preflight-output"
	exit 1
fi
grep "Vault secrets need OCI instance metadata" "$work/preflight-output"
echo "Oracle release secret preflight refuses unavailable instance identity"
printf 'Local\n' > "$work/preflight-sys/class/dmi/id/chassis_asset_tag"
"$bin" vault check-services
echo "Local release secret preflight needs no OCI credentials"
SH_PREFLIGHT
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
