#!/usr/bin/env bash
packages=$HOME/.cache/ts-m1-runtime
mkdir -p "$packages"
inputs=$(python3 "$repo/test/e2e/m1/runtime-inputs.py")
eval "$inputs"
containerd_file=containerd-$containerd_version-linux-$arch.tar.gz
runc_file=runc-$runc_version.$arch
netbird_file=${netbird##*/}
pinned() {
	[[ -e $packages/$1 ]] || { curl -fsSL -o "$work/$1" "$2" && mv "$work/$1" "$packages/$1"; }
	echo "$3  $packages/$1" | sha256sum -c --quiet
}
cache_pins() {
	pinned "$containerd_file" "https://github.com/containerd/containerd/releases/download/v$containerd_version/$containerd_file" "$containerd_sha256"
	pinned "$runc_file" "https://github.com/opencontainers/runc/releases/download/v$runc_version/runc.$arch" "$runc_sha256"
	pinned "$netbird_file" "$netbird" "$netbird_sha256"
}
restore_runtime() {
	cache_hit=false
	[[ ! -e $packages/$containerd_file || ! -e $packages/$runc_file || ! -e $packages/$netbird_file ]] || cache_hit=true
	cache_pins
	sudo tar -C /usr/local -xzf "$packages/$containerd_file"
	sudo install -m 0755 "$packages/$runc_file" /usr/local/sbin/runc
	tar -C "$work" -xzf "$packages/$netbird_file" netbird
	sudo install -m 0755 "$work/netbird" /usr/local/bin/netbird
}
