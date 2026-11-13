set -euo pipefail
bin=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
python=$(python3 -c 'import os,sys;print(os.path.realpath(sys.executable))')
trap 'sudo rm -rf "$work"' EXIT
nice -n 19 go build -ldflags="-s -w" -p 1 -o "$work/updater-preflight" "$here"
mkdir -p "$work/updater-sys/class/dmi/id"
printf 'Local\n' > "$work/updater-sys/class/dmi/id/chassis_asset_tag"
sudo -n unshare --mount --net bash -s -- "$bin" "$work" "$here" "$python" <<'SH_UPDATER'
set -euo pipefail
bin=$1
work=$2
here=$3
python=$4
mount --make-rprivate /
ip link set lo up
mount --bind "$work/updater-sys" /sys
current_system=$(readlink /run/current-system 2>/dev/null || true)
mkdir "$work/updater-run"
mount -t tmpfs -o mode=0755 tmpfs "$work/updater-run"
if [[ -n $current_system ]]; then
 ln -s "$current_system" "$work/updater-run/current-system"
fi
mount --bind "$work/updater-run" /run
"$python" "$here/faults.py" "$work/updater-preflight"
exec "$work/updater-preflight" "$bin"
SH_UPDATER
