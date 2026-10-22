#!/usr/bin/env bash
# Pin containerd and runc on a milestone 1 host (arm64 or amd64); runs as root
# on the host. Ubuntu's containerd 2.2 cannot start ts-orch tasks (the binary-v2
# log scheme needs containerd >= 2.3). Release binaries go to /usr/local, ahead
# of the distro packages, so apt upgrades cannot replace them.
set -euo pipefail

containerd_version=2.4.2
# runc is the version containerd pins in script/setup/runc-version.
runc_version=1.5.2
# The sha256 values are the upstream releases' published checksums.
case $(uname -m) in
aarch64)
	arch=arm64
	containerd_sha256=fdfab81a86192ddb8165d72f116ec985485c9e12505e323c4f4579c48020f276
	runc_sha256=d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0
	;;
x86_64)
	arch=amd64
	containerd_sha256=35880c1dd4627e8ce56526bfabb39c144e83458ffdb197ce6f05d17d94d7d91e
	runc_sha256=599f6f94ff8c5057241eff0d54c3c74f95c34935b6457b33fe545defc61e9488
	;;
*) echo "host-runtime.sh pins arm64 and amd64 binaries only" >&2; exit 1 ;;
esac
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if [[ $(/usr/local/bin/containerd --version 2>/dev/null) != *" v$containerd_version "* ]]; then
	curl -fsSL --retry 3 -o "$tmp/containerd.tar.gz" \
		"https://github.com/containerd/containerd/releases/download/v$containerd_version/containerd-$containerd_version-linux-$arch.tar.gz"
	echo "$containerd_sha256  $tmp/containerd.tar.gz" | sha256sum -c --quiet
	tar -C /usr/local -xzf "$tmp/containerd.tar.gz"
fi
if [[ $(/usr/local/sbin/runc --version 2>/dev/null) != "runc version $runc_version"* ]]; then
	curl -fsSL --retry 3 -o "$tmp/runc" \
		"https://github.com/opencontainers/runc/releases/download/v$runc_version/runc.$arch"
	echo "$runc_sha256  $tmp/runc" | sha256sum -c --quiet
	install -m 0755 "$tmp/runc" /usr/local/sbin/runc
fi

# A fresh host has no distro containerd unit; install upstream's.
if ! systemctl cat containerd.service >/dev/null 2>&1; then
	cat > /etc/systemd/system/containerd.service <<'UNIT'
[Unit]
Description=containerd container runtime
Documentation=https://containerd.io
After=network.target

[Service]
ExecStartPre=-/sbin/modprobe overlay
ExecStart=/usr/local/bin/containerd
Type=notify
Delegate=yes
KillMode=process
Restart=always
RestartSec=5
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
OOMScoreAdjust=-999

[Install]
WantedBy=multi-user.target
UNIT
fi
install -d /etc/systemd/system/containerd.service.d
printf '[Service]\nExecStart=\nExecStart=/usr/local/bin/containerd\n' > /etc/systemd/system/containerd.service.d/10-ts-orch.conf
systemctl daemon-reload
systemctl enable containerd
# Restart only when the running daemon is not the pinned one.
running=$(ctr version 2>/dev/null || true)
[[ $running == *"Server:"*"Version:  v$containerd_version"* ]] || systemctl restart containerd
ctr version
