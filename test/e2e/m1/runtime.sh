#!/usr/bin/env bash
packages=$HOME/.cache/ts-m1-runtime
mkdir -p "$packages"
runtime_pins=$repo/deploy/m1/host-runtime.sh
containerd_version=$(sed -n 's/^containerd_version=//p' "$runtime_pins")
runc_version=$(sed -n 's/^runc_version=//p' "$runtime_pins")
containerd_sha256=$(sed -n '/^aarch64)/,/;;/s/^\tcontainerd_sha256=//p' "$runtime_pins")
runc_sha256=$(sed -n '/^aarch64)/,/;;/s/^\trunc_sha256=//p' "$runtime_pins")
netbird_pin=$repo/internal/netbird/manager/server_cli.go
netbird=$(sed -n 's/.*Arm64 = client.Archive{URL: "\([^"]*\)".*/\1/p' "$netbird_pin")
netbird_sha256=$(sed -n '/Arm64 = client.Archive/{n;s/.*SHA256: "\([0-9a-f]*\)".*/\1/p}' "$netbird_pin")
containerd_file=containerd-$containerd_version-linux-arm64.tar.gz
runc_file=runc-$runc_version.arm64
netbird_file=${netbird##*/}
pinned() {
	[[ -e $packages/$1 ]] || { curl -fsSL -o "$work/$1" "$2" && mv "$work/$1" "$packages/$1"; }
	echo "$3  $packages/$1" | sha256sum -c --quiet
}
cache_pins() {
	pinned "$containerd_file" "https://github.com/containerd/containerd/releases/download/v$containerd_version/$containerd_file" "$containerd_sha256"
	pinned "$runc_file" "https://github.com/opencontainers/runc/releases/download/v$runc_version/runc.arm64" "$runc_sha256"
	pinned "$netbird_file" "$netbird" "$netbird_sha256"
}
restore_runtime() {
	cache_hit=false
	if [[ -e $packages/$containerd_file && -e $packages/$runc_file && -e $packages/$netbird_file ]]; then
		cache_hit=true
		cache_pins
		sudo tar -C /usr/local -xzf "$packages/$containerd_file"
		sudo install -m 0755 "$packages/$runc_file" /usr/local/sbin/runc
		tar -C "$work" -xzf "$packages/$netbird_file" netbird
		sudo install -m 0755 "$work/netbird" /usr/local/bin/netbird
	fi
}
