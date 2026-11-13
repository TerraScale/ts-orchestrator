#!/usr/bin/env bash
set -euo pipefail
umask 022
root=$1
binary=$2
image=$3
archive=$4
mount --make-rprivate /
mkdir -p "$root/cgroup"
mount --bind /sys/fs/cgroup "$root/cgroup"
mkdir -p /run/netns
mount -t tmpfs tmpfs /run/netns
ip link set lo up
ip link add c18 type bridge
ip addr add 10.231.0.1/24 dev c18
ip link set c18 up
cleanup() {
	for name in c18a c18b; do
		if [[ -f $root/$name/agent.pid ]]; then kill "$(cat "$root/$name/agent.pid")" 2>/dev/null || true; fi
		if [[ -S $root/$name/containerd.sock ]]; then
			while read -r task; do
				[[ -z $task ]] || ctr --timeout 5s --address "$root/$name/containerd.sock" --namespace terrascale tasks kill --signal SIGKILL --all "$task" || true
			done < <(ctr --timeout 5s --address "$root/$name/containerd.sock" --namespace terrascale tasks ls -q)
		fi
		if [[ -f $root/$name/daemon.pid ]]; then kill "$(cat "$root/$name/daemon.pid")" 2>/dev/null || true; fi
	done
	for name in c18a c18b; do
		ip netns pids "$name" | xargs -r kill -KILL 2>/dev/null || true
		ip netns del "$name" || true
	done
	wait || true
}
trap cleanup EXIT
for name in c18a c18b; do
	ip netns add "$name"
	ip link add "$name-host" type veth peer name "$name-peer"
	ip link set "$name-host" master c18
	ip link set "$name-host" up
	ip link set "$name-peer" netns "$name"
	address=10.231.0.2
	[[ $name == c18a ]] || address=10.231.0.3
	ip -n "$name" addr add "$address/24" dev "$name-peer"
	ip -n "$name" link set "$name-peer" up
	ip -n "$name" link set lo up
	mkdir -p "$root/$name/data/c18"
	install -m 0755 "$binary" "$root/$name/data/c18/lifecycle"
	ip netns exec "$name" unshare --mount --uts bash -s -- "$root" "$name" "$binary" "$archive" <<'SH' >"$root/$name/output" 2>&1 &
set -euo pipefail
root=$1
name=$2
binary=$3
archive=$4
hostname "$name"
mount --make-rprivate /
mount --bind "$root/cgroup" /sys/fs/cgroup
mount -t tmpfs tmpfs /var/lib
mkdir -p /var/run/nri
mount -t tmpfs tmpfs /var/run/nri
mkdir -p /var/lib/ts-data
mount --bind "$root/$name/data" /var/lib/ts-data
containerd --root "$root/$name/content" --state "$root/$name/runtime" --address "$root/$name/containerd.sock" >"$root/$name/containerd-output" 2>&1 &
daemon=$!
echo "$daemon" >"$root/$name/daemon.pid"
trap 'kill "$daemon" 2>/dev/null || true; wait "$daemon" || true' EXIT
"$binary" runtime "$root/$name/containerd.sock"
ctr --address "$root/$name/containerd.sock" --timeout 30s version
ctr --address "$root/$name/containerd.sock" --namespace terrascale images import "$archive"
echo "$$" >"$root/$name/agent.pid"
exec "$binary" node "$root" "$name"
SH
done
if ! "$binary" "$root" "$image"; then
	tail -n 80 "$root/c18a/output" "$root/c18b/output"
	exit 1
fi
test "$(grep -c 'data-owning task unresponsive for five minutes' "$root/c18a/output")" -eq 1
test "$(grep -c 'task readiness unresponsive window cleared' "$root/c18a/output")" -eq 1
