#!/usr/bin/env bash
set -euo pipefail
work=$1
binaries=$2
image=$3
mount --make-rprivate /
ip link set lo up
containerd --root "$work/image/content" --state "$work/image/runtime" --address "$work/image/containerd.sock" >"$work/containerd-output" 2>&1 &
daemon=$!
cleanup() { kill "$daemon" 2>/dev/null || true; wait "$daemon" || true; }
trap cleanup EXIT
"$binaries/lifecycle" runtime "$work/image/containerd.sock"
ctr --address "$work/image/containerd.sock" --namespace terrascale images pull "$image"
ctr --address "$work/image/containerd.sock" --namespace terrascale images export "$work/busybox.tar" "$image"
kill "$daemon"
wait "$daemon" || true
trap - EXIT
bash "$(dirname "$0")/run.sh" "$work/readiness" "$binaries/lifecycle" "$image" "$work/busybox.tar" "$binaries/server"
