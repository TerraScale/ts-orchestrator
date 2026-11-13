set -euo pipefail
umask 022
binary=$(realpath "$1")
work=$(mktemp -d)
cleanup() { sudo rm -rf "$work"; }
trap cleanup EXIT
sudo env "PATH=$PATH" unshare --mount --net --uts bash -s -- "$binary" "$work" <<'SH'
set -euo pipefail
umask 022
binary=$1
work=$2
mount --make-rprivate /
hostname boot-host
ip link set lo up
current_system=""
if [[ -L /run/current-system ]]; then current_system=$(readlink -f /run/current-system); fi
resolv_target=$(readlink -f /etc/resolv.conf)
cp /etc/resolv.conf "$work/resolv.conf"
mount -t tmpfs tmpfs /run
if [[ -n $current_system ]]; then "$current_system/sw/bin/ln" -s "$current_system" /run/current-system; fi
if [[ $resolv_target == /run/* ]]; then
	mkdir -p "$(dirname "$resolv_target")"
	cp "$work/resolv.conf" "$resolv_target"
fi
exec "$binary" lane "$work"
SH
