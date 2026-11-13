package regionhost

import (
	"encoding/base64"
	"fmt"
	"io/fs"
	"regexp"
)

var (
	sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)
	plainURL  = regexp.MustCompile(`^https://[A-Za-z0-9./_:%-]+$`)
)

func CloudInit(files fs.FS, binaryURL, sum string, formatted bool) (string, error) {
	if !sha256Hex.MatchString(sum) || !plainURL.MatchString(binaryURL) {
		return "", fmt.Errorf("release asset needs a plain https URL and a lowercase sha256")
	}
	runtime, err := fs.ReadFile(files, "host-runtime.sh")
	if err != nil {
		return "", err
	}
	unit, err := fs.ReadFile(files, "ts-orch.service")
	if err != nil {
		return "", err
	}
	companion, err := fs.ReadFile(files, "services/netbird-server.service")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`#!/bin/bash
set -euo pipefail
install -d -m 0755 /usr/local/lib/ts-orch
echo '%s' | base64 -d > /usr/local/lib/ts-orch/data-volume.sh
bash /usr/local/lib/ts-orch/data-volume.sh %t
echo '%s' | base64 -d | bash
if ! command -v netbird >/dev/null; then
	curl -fsSL https://pkgs.netbird.io/debian/public.key | gpg --dearmor --yes -o /usr/share/keyrings/netbird-archive-keyring.gpg
	echo 'deb [signed-by=/usr/share/keyrings/netbird-archive-keyring.gpg] https://pkgs.netbird.io/debian stable main' > /etc/apt/sources.list.d/netbird.list
	apt-get update -qq
	DEBIAN_FRONTEND=noninteractive apt-get install -y -qq netbird
fi
systemctl is-enabled --quiet netbird || netbird service install
systemctl enable --now netbird
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
curl -fsSL --retry 3 -o "$tmp" '%s'
echo '%s  '"$tmp" | sha256sum -c --quiet
install -m 0755 "$tmp" /usr/local/bin/terrascale-orchestrator
ln -sfn terrascale-orchestrator /usr/local/bin/ts-orch
install -d -m 0700 /var/lib/ts-orch
install -d -m 0755 /var/lib/ts-data /var/lib/ts-data/terrabase
echo '%s' | base64 -d > /etc/systemd/system/ts-orch.service
echo '%s' | base64 -d > /etc/systemd/system/netbird-server.service
chmod 0644 /etc/systemd/system/ts-orch.service /etc/systemd/system/netbird-server.service
systemctl daemon-reload
systemctl enable ts-orch.service netbird-server.service
systemctl restart ts-orch.service netbird-server.service
`, base64.StdEncoding.EncodeToString([]byte(dataVolumeSetup)), formatted, base64.StdEncoding.EncodeToString(runtime), binaryURL, sum, base64.StdEncoding.EncodeToString(unit),
		base64.StdEncoding.EncodeToString(companion)), nil
}

const dataVolumeSetup = `#!/usr/bin/env bash
set -euo pipefail

formatted=$1
device=/dev/oracleoci/oraclevdb
udevadm wait "$device"
test -b "$device"
probe_failed() {
	echo "data volume probe failed: $*" >&2
	exit 1
}
types=$(lsblk -nr -o TYPE "$device") || probe_failed lsblk-types
test -n "$types" || probe_failed lsblk-types
test "$(printf '%s\n' "$types" | wc -l)" -eq 1
parent=$(lsblk -dn -o PKNAME "$device") || probe_failed lsblk-parent
test -z "$parent"
mounts=$(lsblk -nr -o MOUNTPOINT "$device") || probe_failed lsblk-mounts
test -z "$(printf '%s' "$mounts" | tr -d '[:space:]')"
if blkid -p "$device" >/dev/null; then
	:
else
	status=$?
	if test "$status" -ne 2; then
		probe_failed "blkid ($status)"
	fi
	test "$formatted" = false
	signatures=$(wipefs --no-act --noheadings --output TYPE "$device") || probe_failed wipefs
	test -z "$signatures"
	size=$(blockdev --getsize64 "$device") || probe_failed blockdev-size
	[[ $size =~ ^[0-9]+$ ]] || probe_failed blockdev-size
	gib=$((1024 * 1024 * 1024))
	mib=$((1024 * 1024))
	test "$size" -ge "$((2 * gib))" || probe_failed minimum-size
	check_zero() {
		dd if="$device" bs=1M skip="$1" count="$2" iflag=skip_bytes,count_bytes,fullblock status=none | cmp -n "$2" - /dev/zero || probe_failed "sample $1 length $2"
	}
	check_zero 0 "$gib"
	check_zero "$((size - gib))" "$gib"
	for ((offset=gib; offset<size-gib; offset+=gib)); do
		check_zero "$offset" "$mib"
	done
	mkfs.ext4 -q "$device"
fi
fstype=$(blkid -p -s TYPE -o value "$device") || probe_failed blkid-type
test "$fstype" = ext4
uuid=$(blkid -p -s UUID -o value "$device") || probe_failed blkid-uuid
[[ $uuid =~ ^[0-9a-f-]{36}$ ]]
install -d -m 0755 /var/lib/ts-data
contents=$(ls -A /var/lib/ts-data) || probe_failed data-directory
test -z "$contents"
entry="UUID=$uuid /var/lib/ts-data ext4 defaults 0 2"
grep -Fxq "$entry" /etc/fstab || printf '%s\n' "$entry" >> /etc/fstab
mount /var/lib/ts-data
install -d -m 0755 /var/lib/ts-data/terrabase
install -d -m 0700 /var/lib/ts-data/ts-orch /var/lib/ts-orch
contents=$(ls -A /var/lib/ts-orch) || probe_failed state-directory
test -z "$contents"
entry='/var/lib/ts-data/ts-orch /var/lib/ts-orch none bind 0 0'
grep -Fxq "$entry" /etc/fstab || printf '%s\n' "$entry" >> /etc/fstab
mount /var/lib/ts-orch
for unit in ts-orch netbird-server; do
install -d -m 0755 "/etc/systemd/system/$unit.service.d"
cat > "/etc/systemd/system/$unit.service.d/data-volume.conf" <<'UNIT'
[Unit]
RequiresMountsFor=/var/lib/ts-data /var/lib/ts-orch
BindsTo=var-lib-ts\x2ddata.mount var-lib-ts\x2dorch.mount
After=var-lib-ts\x2ddata.mount var-lib-ts\x2dorch.mount

[Service]
ExecStartPre=/usr/bin/mountpoint -q /var/lib/ts-data
ExecStartPre=/usr/bin/mountpoint -q /var/lib/ts-orch
UNIT
done
systemctl daemon-reload
`
