#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$here/runtime.sh"
restore_runtime
begin "regional OCIR selection pulled into containerd"
runtime_dir=$work/containerd
install -d -m 0700 "$runtime_dir"
sudo containerd --root "$runtime_dir/root" --state "$runtime_dir/state" --address "$runtime_dir/containerd.sock" >"$work/containerd.log" 2>&1 &
wait_for 30 sudo test -S "$runtime_dir/containerd.sock"
sudo "$(dirname "$bin")/ocir" "$runtime_dir/containerd.sock" "$work/executor"
sudo pkill -f -- "--address $runtime_dir/containerd.sock"
end "regional OCIR -> signed selection, provenance refusals and a containerd pull of the fleet image name"
