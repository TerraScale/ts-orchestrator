#!/usr/bin/env bash
set -euo pipefail

if ! command -v chronyc >/dev/null; then
    (
        apt_dir=$(mktemp -d)
        trap 'rm -rf "$apt_dir"' EXIT
        install -d -m 0755 "$apt_dir" "$apt_dir/lists/partial" "$apt_dir/cache/archives/partial"
        apt-get -o Dir::State::Lists="$apt_dir/lists" -o Dir::Cache="$apt_dir/cache" update -qq
        DEBIAN_FRONTEND=noninteractive apt-get -o Dir::State::Lists="$apt_dir/lists" -o Dir::Cache="$apt_dir/cache" -o DPkg::Lock::Timeout=300 install -y -qq chrony
    )
fi
cat > /etc/chrony/chrony.conf <<'CHRONY'
server 169.254.169.254 iburst minpoll 4 maxpoll 6
driftfile /var/lib/chrony/chrony.drift
makestep 0.1 3
rtcsync
leapsectz right/UTC
CHRONY
systemctl enable --now chrony
systemctl restart chrony
chronyc waitsync 30 0.01 0 1

case $(uname -m) in
aarch64)
arch=arm64
containerd_version=2.4.2
runc_version=1.5.2
containerd_sha256=fdfab81a86192ddb8165d72f116ec985485c9e12505e323c4f4579c48020f276
runc_sha256=d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0
netbird_version=0.81.3
netbird=https://github.com/netbirdio/netbird/releases/download/v0.81.3/netbird_0.81.3_linux_arm64.tar.gz
netbird_sha256=980eef938177108bdfa7d802566b6309123592a58631349a78f11cd97c76c22d
netbird_binary_sha256=da0c759ba50c0e1fd652d6f584587db3d3523dcc6bd18c11fab479969a3057ce
;;
x86_64)
arch=amd64
containerd_version=2.4.2
runc_version=1.5.2
containerd_sha256=35880c1dd4627e8ce56526bfabb39c144e83458ffdb197ce6f05d17d94d7d91e
runc_sha256=599f6f94ff8c5057241eff0d54c3c74f95c34935b6457b33fe545defc61e9488
netbird_version=0.81.3
netbird=https://github.com/netbirdio/netbird/releases/download/v0.81.3/netbird_0.81.3_linux_amd64.tar.gz
netbird_sha256=cbdea310068e35449f034544d5137fefee8f6d948fffd020883ffc8b3bab63b1
netbird_binary_sha256=2bef5a5a44249443c0c492883e1b243ff5bc9d835266a8c5644a2a664bb3b846
;;
*) echo "host runtime pins support arm64 and amd64 only" >&2; exit 1 ;;
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
running=$(ctr version 2>/dev/null || true)
[[ $running == *"Server:"*"Version:  v$containerd_version"* ]] || systemctl restart containerd
ctr version

if ! echo "$netbird_binary_sha256  /usr/local/bin/netbird" | sha256sum -c --status; then
	curl -fsSL -o "$tmp/netbird.tar.gz" "$netbird"
	echo "$netbird_sha256  $tmp/netbird.tar.gz" | sha256sum -c --quiet
	tar --no-same-owner -C "$tmp" -xzf "$tmp/netbird.tar.gz" netbird
	echo "$netbird_binary_sha256  $tmp/netbird" | sha256sum -c --quiet
	install -m 0755 "$tmp/netbird" /usr/local/bin/netbird.next
	mv -f /usr/local/bin/netbird.next /usr/local/bin/netbird
fi
[[ $(/usr/local/bin/netbird version) == "$netbird_version" ]]
bash -s -- /usr/local/bin/netbird "$netbird_binary_sha256" <<'NETBIRD_SERVICE'
#!/usr/bin/env bash
set -euo pipefail
binary=$1
expected=$2
echo "$expected  $binary" | sha256sum -c --status
properties=$(systemctl show --property=LoadState --property=MainPID netbird)
load_state=$(sed -n 's/^LoadState=//p' <<< "$properties")
pid=$(sed -n 's/^MainPID=//p' <<< "$properties")
[[ $pid =~ ^[0-9]+$ ]]
unit=missing
process=stopped
if [[ $load_state != not-found ]]; then
	state=$(busctl --json=short get-property org.freedesktop.systemd1 /org/freedesktop/systemd1/unit/netbird_2eservice org.freedesktop.systemd1.Service ExecStart |
		python3 -c '
import json
import os
import sys
from pathlib import Path

commands = json.load(sys.stdin)["data"]
binary, pid = sys.argv[1:]
canonical = len(commands) == 1 and commands[0][0] == binary and commands[0][1][:3] == [binary, "service", "run"]
matches = False
if pid != "0":
    running = [os.fsdecode(arg) for arg in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")[:-1]]
    matches = len(commands) == 1 and commands[0][1] == running
print("canonical" if canonical else "different", "matches" if matches else "different")
' "$binary" "$pid")
	read -r unit process <<< "$state"
fi
action=start
if [[ $pid != 0 ]]; then
	running=$(sha256sum "/proc/$pid/exe")
	[[ $running == "$expected "* && $process == matches ]] || action=restart
fi
if [[ $unit != canonical ]]; then
	if [[ $load_state == not-found ]]; then
		"$binary" service install
	else
		systemctl stop netbird
		"$binary" service reconfigure
	fi
	action=restart
fi
systemctl enable netbird
systemctl "$action" netbird
NETBIRD_SERVICE
