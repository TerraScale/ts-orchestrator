set -euo pipefail
bin=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
python=$(python3 -c 'import os,sys;print(os.path.realpath(sys.executable))')
trap 'sudo rm -rf "$work"' EXIT
nice -n 19 go build -ldflags="-s -w" -p 1 -o "$work/updater-preflight" "$here"
previous=dc098b1fca6faf0b3ab683f76f45c16e541e5f00
repo=$(git -C "$here" rev-parse --show-toplevel)
git -C "$repo" cat-file -e "$previous^{commit}" 2>/dev/null || git -C "$repo" fetch -q --depth 1 origin "$previous"
mkdir "$work/previous-src"
git -C "$repo" archive "$previous" | tar -x -C "$work/previous-src"
cp -r "$here/previous" "$work/previous-src/updater-previous"
(cd "$work/previous-src" && nice -n 19 go build -trimpath -ldflags="-s -w" -o "$work/previous-updater" ./updater-previous)
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
exec "$work/updater-preflight" "$bin" "$work/previous-updater"
SH_UPDATER
