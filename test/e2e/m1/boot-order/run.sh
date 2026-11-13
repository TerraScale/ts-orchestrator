set -euo pipefail
umask 022
binary=$(realpath "$1")
work=$(mktemp -d)
pids=()
cleanup() {
	for pid in "${pids[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
	for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
	sudo rm -rf "$work"
}
trap cleanup EXIT
run() {
exec sudo env "PATH=$PATH" unshare --mount --net --uts bash -s -- "$binary" "$work/$1" "$1" <<'SH'
set -euo pipefail
umask 022
binary=$1
work=$2
mode=$3
mkdir -p "$work"
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
exec "$binary" lane "$work" "$mode"
SH
}
run management &
pids+=("$!")
run peer &
pids+=("$!")
for pid in "${pids[@]}"; do wait "$pid"; done
pids=()
echo "boot-order: management host and other host recovered; peers remained gated; running tasks survived agent restart"
