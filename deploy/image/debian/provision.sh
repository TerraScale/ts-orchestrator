#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

source /run/ts-image-env

rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources
echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/$TS_SNAPSHOT/ trixie main" > /etc/apt/sources.list.d/ts-snapshot.list
echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/$TS_SNAPSHOT/ trixie-security main" >> /etc/apt/sources.list.d/ts-snapshot.list
apt-get update -qq

apt-get install -y -qq chrony nftables python3 e2fsprogs util-linux curl ca-certificates cloud-guest-utils cloud-initramfs-growroot sudo

useradd --create-home --shell /bin/bash --groups sudo terrascale
install -d -m 0700 -o terrascale -g terrascale /home/terrascale/.ssh
touch /home/terrascale/.ssh/authorized_keys
chown terrascale:terrascale /home/terrascale/.ssh/authorized_keys
chmod 0600 /home/terrascale/.ssh/authorized_keys
printf 'terrascale ALL=(ALL:ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/terrascale
chmod 0440 /etc/sudoers.d/terrascale

cat > /etc/chrony/chrony.conf <<'CHRONY'
server 169.254.169.254 iburst minpoll 4 maxpoll 6
driftfile /var/lib/chrony/chrony.drift
makestep 0.1 3
rtcsync
leapsectz right/UTC
CHRONY
systemctl enable chrony

containerd_version=2.4.2
runc_version=1.5.2
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
curl -fsSL -o containerd.tar.gz \
	"https://github.com/containerd/containerd/releases/download/v$containerd_version/containerd-$containerd_version-linux-$TS_ARCH.tar.gz"
echo "$TS_CONTAINERD_SHA256  containerd.tar.gz" | sha256sum -c --quiet
tar -C /usr/local -xzf containerd.tar.gz
curl -fsSL -o runc \
	"https://github.com/opencontainers/runc/releases/download/v$runc_version/runc.$TS_ARCH"
echo "$TS_RUNC_SHA256  runc" | sha256sum -c --quiet
install -m 0755 runc /usr/local/sbin/runc

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
install -d /etc/systemd/system/containerd.service.d
printf '[Service]\nExecStart=\nExecStart=/usr/local/bin/containerd\n' > /etc/systemd/system/containerd.service.d/10-ts-orch.conf
systemctl enable containerd

curl -fsSL -o netbird.tar.gz "$TS_NETBIRD_TARBALL_URL"
echo "$TS_NETBIRD_SHA256  netbird.tar.gz" | sha256sum -c --quiet
tar -C /usr/local/bin -xzf netbird.tar.gz netbird
install -d /run/systemd/system
netbird service install
rmdir /run/systemd/system
systemctl enable netbird

curl -fsSL -o terrascale-orchestrator "$TS_BINARY_URL"
echo "$TS_BINARY_SHA256  terrascale-orchestrator" | sha256sum -c --quiet
install -m 0755 terrascale-orchestrator /usr/local/bin/terrascale-orchestrator
ln -sfn terrascale-orchestrator /usr/local/bin/ts-orch
install -d -m 0755 /usr/local/lib/ts-orch
printf '%s\n' "$TS_BINARY_SHA256" > /usr/local/lib/ts-orch/image-release.sha256

for unit in /etc/systemd/system/ts-orch.service /etc/systemd/system/ts-node-init.service /etc/systemd/system/ts-ssh-keys.service /etc/systemd/system/netbird-server.service; do
	systemctl enable "${unit##*/}"
done
systemctl mask apt-daily.timer apt-daily-upgrade.timer man-db.timer e2scrub_all.timer
/usr/local/sbin/fstab-growroot

apt-get purge -y -qq cloud-init unattended-upgrades
apt-get autoremove -y -qq
install -d /etc/systemd/network
cat > /etc/systemd/network/10-ts-host.network <<'NETWORK'
[Match]
Name=en* eth*

[Network]
DHCP=yes
IPv6AcceptRA=yes
NETWORK
systemctl enable systemd-networkd systemd-networkd-wait-online systemd-resolved ssh
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id /etc/ssh/ssh_host_*
apt-get clean
rm -rf /var/lib/apt/lists/* /var/lib/cloud /var/log/cloud-init* /run/ts-image-env /run/ts-image-provision.sh
