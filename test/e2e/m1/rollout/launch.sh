#!/usr/bin/env bash
set -euo pipefail
root=$1
bin=$2
mode=$3
shift 3
hostname "$(basename "$root")"
mount -t cgroup2 none /sys/fs/cgroup
mkdir -p "$root/run" "$root/peers" "$root/nri" /run/ts-orch/peers /run/nri
mount --bind "$root/run" /run/containerd
mount --bind "$root/peers" /run/ts-orch/peers
mount --bind "$root/nri" /run/nri
if [[ $mode == containerd ]]; then
 exec "$bin" --address "$root/run/containerd.sock" --root "$root/containerd" --state "$root/containerd-state"
fi
if [[ $mode == service ]]; then
 mkdir -p /var/lib/ts-orch
 mount --bind "$root" /var/lib/ts-orch
 exec "$bin" service "$@"
fi
exec "$bin" "$mode" "$root" "$@"
