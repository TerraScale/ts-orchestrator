package regionhost

import (
	"encoding/base64"
	"fmt"
	"io/fs"
	"regexp"
)

var (
	sha256Hex      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	filesystemUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	volumeIdentity = regexp.MustCompile(`^ocid1\.volume\.oc[0-9]+\.[a-z0-9-]+\.[a-zA-Z0-9]+$`)
	diskSerial     = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
	plainURL       = regexp.MustCompile(`^https://[A-Za-z0-9./_:%-]+$`)
)

func CloudInit(files fs.FS, binaryURL, sum, volumeID, expectedUUID, expectedSerial string, mayFormat bool) (string, error) {
	if !sha256Hex.MatchString(sum) || !plainURL.MatchString(binaryURL) {
		return "", fmt.Errorf("release asset needs a plain https URL and a lowercase sha256")
	}
	if !volumeIdentity.MatchString(volumeID) || (expectedUUID != "" && !filesystemUUID.MatchString(expectedUUID)) || (!mayFormat && expectedUUID == "") || (expectedSerial != "" && !diskSerial.MatchString(expectedSerial)) || (mayFormat && (expectedUUID != "" || expectedSerial != "")) {
		return "", fmt.Errorf("data volume requires an identity and an expected UUID unless created in this run")
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
bash /usr/local/lib/ts-orch/data-volume.sh %t '%s' '%s' '%s'
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
`, base64.StdEncoding.EncodeToString([]byte(dataVolumeSetup)), mayFormat, volumeID, expectedUUID, expectedSerial, base64.StdEncoding.EncodeToString(runtime), binaryURL, sum, base64.StdEncoding.EncodeToString(unit),
		base64.StdEncoding.EncodeToString(companion)), nil
}

const dataVolumeSetup = `#!/usr/bin/env bash
set -euo pipefail
may_format=$1
expected_volume=$2
expected_uuid=$3
expected_serial=$4
[[ $may_format == true || $may_format == false ]] || exit 1
[[ $expected_volume =~ ^ocid1\.volume\.oc[0-9]+\.[a-z0-9-]+\.[a-zA-Z0-9]+$ ]] || exit 1
if test -n "$expected_uuid"; then
 [[ $expected_uuid =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || exit 1
fi
if test -n "$expected_serial"; then
 [[ $expected_serial =~ ^[0-9a-fA-F]{32}$ ]] || exit 1
fi
if test "$may_format" = true; then
 test -z "$expected_uuid" && test -z "$expected_serial" || exit 1
else
 test -n "$expected_uuid" || exit 1
fi
device=/dev/oracleoci/oraclevdb
record=/var/lib/ts-orch-bootstrap/format-consumed
probe_failed() {
 echo "data volume refused: $*" >&2
 exit 1
}
arrival=$(timeout 120 udevadm wait "$device" 2>&1) || probe_failed device-wait
test -z "$arrival" || probe_failed device-wait-output
test -b "$device" || probe_failed block-device
resolved=$(timeout 10 readlink -f "$device") || probe_failed device-path
test -n "$resolved" || probe_failed device-path
types=$(timeout 10 lsblk -nr -o TYPE "$device" 2>&1) || probe_failed lsblk-types
test -n "$types" && test "$types" = disk || probe_failed lsblk-types
parent=$(timeout 10 lsblk -dn -o PKNAME "$device" 2>&1) || probe_failed lsblk-parent
test -z "$parent" || probe_failed lsblk-parent
model=$(timeout 10 lsblk -dnr -o MODEL "$device" 2>&1) || probe_failed disk-model
test -n "$model" && test "$model" = BlockVolume || probe_failed disk-model
serial=$(timeout 10 lsblk -dnr -o SERIAL "$device" 2>&1) || probe_failed disk-serial
[[ $serial =~ ^[0-9a-fA-F]{32}$ ]] || probe_failed disk-serial
wwn=$(timeout 10 lsblk -dnr -o WWN "$device" 2>&1) || probe_failed disk-wwn
test -n "$wwn" && test "$wwn" = "0x$serial" || probe_failed disk-wwn
if test -n "$expected_serial"; then
 test "$serial" = "$expected_serial" || probe_failed expected-serial
fi
mounts=$(timeout 10 lsblk -nr -o MOUNTPOINT "$device" 2>&1) || probe_failed lsblk-mounts
mounts=$(printf '%s' "$mounts" | tr -d '[:space:]') || probe_failed lsblk-mounts
test -z "$mounts" || probe_failed lsblk-mounts
size=$(timeout 10 blockdev --getsize64 "$device" 2>&1) || probe_failed blockdev-size
[[ $size =~ ^[0-9]+$ ]] || probe_failed blockdev-size
if test "$may_format" = true && test -z "$expected_uuid"; then
 test ! -e "$record" || probe_failed permission-consumed
 instance=$(timeout 10 curl -fsS --max-time 8 -H 'Authorization: Bearer Oracle' http://169.254.169.254/opc/v2/instance/) || probe_failed instance-binding
 printf '%s' "$instance" | timeout 10 python3 -c '
import json, re, sys
instance = json.load(sys.stdin)
volume, permission = sys.argv[1:]
if not isinstance(instance, dict):
 sys.exit("invalid instance document")
identity = instance.get("id")
metadata = instance.get("metadata")
if not isinstance(identity, str) or not identity.strip() or not isinstance(metadata, dict):
 sys.exit("missing instance identity or launch metadata")
bound_volume = metadata.get("terrascale-data-volume")
bound_permission = metadata.get("terrascale-data-may-format")
if not isinstance(bound_volume, str) or not re.fullmatch(r"ocid1\.volume\.oc[0-9]+\.[a-z0-9-]+\.[a-zA-Z0-9]+", bound_volume):
 sys.exit("invalid launch volume")
if not isinstance(bound_permission, str) or bound_permission not in ("true", "false"):
 sys.exit("invalid launch permission")
if bound_volume != volume or bound_permission != permission:
 sys.exit("instance format binding mismatch")
' "$expected_volume" "$may_format" || probe_failed instance-binding
 gib=$((1024 * 1024 * 1024))
 mib=$((1024 * 1024))
 test "$size" -ge "$((2 * gib))" || probe_failed minimum-size
 check_zero() {
  timeout 120 dd if="$device" bs=1M skip="$1" count="$2" iflag=skip_bytes,count_bytes,fullblock status=none | timeout 120 cmp -n "$2" - /dev/zero || probe_failed "sample $1 length $2"
 }
 check_zero 0 "$gib"
 check_zero "$((size - gib))" "$gib"
 for ((offset=gib; offset<size-gib; offset+=gib)); do
  check_zero "$offset" "$mib"
 done
 if signature=$(timeout 10 blkid -p "$device" 2>&1); then
  probe_failed blkid-signature
 else
  status=$?
  test "$status" -eq 2 || probe_failed "blkid ($status)"
  test -z "$signature" || probe_failed blkid-output
 fi
 signatures=$(timeout 10 wipefs --no-act --noheadings --output TYPE "$device" 2>&1) || probe_failed wipefs
 test -z "$signatures" || probe_failed wipefs-signature
 filesystems=$(timeout 10 lsblk -nr -o FSTYPE "$device" 2>&1) || probe_failed lsblk-filesystems
 filesystems=$(printf '%s' "$filesystems" | tr -d '[:space:]') || probe_failed lsblk-filesystems
 test -z "$filesystems" || probe_failed lsblk-filesystems
 consumed_at=$(timeout 10 date -u +%FT%TZ) || probe_failed format-time
 [[ $consumed_at =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || probe_failed format-time
 install -d -m 0700 /var/lib/ts-orch-bootstrap
 (set -o noclobber; printf 'volume=%s\nserial=%s\nsize=%s\ntime=%s\n' "$expected_volume" "$serial" "$size" "$consumed_at" > "$record") || probe_failed permission-consumed
 sync -f "$record" || probe_failed durable-permission
 sync -f /var/lib/ts-orch-bootstrap || probe_failed durable-directory
 mkfs.ext4 -q "$device"
fi
fstype=$(timeout 10 blkid -p -s TYPE -o value "$device" 2>&1) || probe_failed blkid-type
test -n "$fstype" && test "$fstype" = ext4 || probe_failed filesystem-type
uuid=$(timeout 10 blkid -p -s UUID -o value "$device" 2>&1) || probe_failed blkid-uuid
[[ $uuid =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || probe_failed filesystem-uuid
if test -n "$expected_uuid"; then
 test "$uuid" = "$expected_uuid" || probe_failed expected-uuid
elif test "$may_format" != true; then
 probe_failed missing-expected-uuid
fi
install -d -m 0755 /var/lib/ts-data
contents=$(timeout 10 ls -A /var/lib/ts-data) || probe_failed data-directory
test -z "$contents" || probe_failed data-directory
install -d -m 0755 /etc/ts-orch
printf '%s\n' "$uuid" > /etc/ts-orch/data-volume-uuid
printf '%s\n' "$serial" > /etc/ts-orch/data-volume-serial
entry="UUID=$uuid /var/lib/ts-data ext4 defaults 0 2"
grep -Fxq "$entry" /etc/fstab || printf '%s\n' "$entry" >> /etc/fstab
mount /var/lib/ts-data
install -d -m 0755 /var/lib/ts-data/terrabase
install -d -m 0700 /var/lib/ts-data/ts-orch /var/lib/ts-orch
contents=$(timeout 10 ls -A /var/lib/ts-orch) || probe_failed state-directory
test -z "$contents" || probe_failed state-directory
entry='/var/lib/ts-data/ts-orch /var/lib/ts-orch none bind 0 0'
grep -Fxq "$entry" /etc/fstab || printf '%s\n' "$entry" >> /etc/fstab
mount /var/lib/ts-orch
cat > /usr/local/lib/ts-orch/data-mount-check.sh <<'CHECK'
set -euo pipefail
mountpoint -q /var/lib/ts-data
mountpoint -q /var/lib/ts-orch
uuid=$(findmnt -rn -M /var/lib/ts-data -o UUID) || exit 1
test -n "$uuid" || exit 1
expected_uuid=$(cat /etc/ts-orch/data-volume-uuid) || exit 1
test -n "$expected_uuid" || exit 1
test "$uuid" = "$expected_uuid" || exit 1
source=$(findmnt -rn -M /var/lib/ts-data -o SOURCE) || exit 1
test -n "$source" || exit 1
actual=$(readlink -f "$source") || exit 1
test -n "$actual" || exit 1
expected=$(readlink -f /dev/oracleoci/oraclevdb) || exit 1
test -n "$expected" || exit 1
test "$actual" = "$expected" || exit 1
serial=$(lsblk -dnr -o SERIAL "$expected") || exit 1
[[ $serial =~ ^[0-9a-fA-F]{32}$ ]] || exit 1
expected_serial=$(cat /etc/ts-orch/data-volume-serial) || exit 1
[[ $expected_serial =~ ^[0-9a-fA-F]{32}$ ]] || exit 1
test "$serial" = "$expected_serial" || exit 1
data_device=$(findmnt -rn -M /var/lib/ts-data -o MAJ:MIN) || exit 1
test -n "$data_device" || exit 1
state_device=$(findmnt -rn -M /var/lib/ts-orch -o MAJ:MIN) || exit 1
test -n "$state_device" || exit 1
test "$state_device" = "$data_device" || exit 1
data_root=$(findmnt -rn -M /var/lib/ts-data -o FSROOT) || exit 1
test -n "$data_root" || exit 1
test "$data_root" = / || exit 1
state_root=$(findmnt -rn -M /var/lib/ts-orch -o FSROOT) || exit 1
test -n "$state_root" || exit 1
test "$state_root" = /ts-orch || exit 1
CHECK
for unit in ts-orch netbird-server; do
install -d -m 0755 "/etc/systemd/system/$unit.service.d"
cat > "/etc/systemd/system/$unit.service.d/data-volume.conf" <<'UNIT'
[Unit]
RequiresMountsFor=/var/lib/ts-data /var/lib/ts-orch
BindsTo=var-lib-ts\x2ddata.mount var-lib-ts\x2dorch.mount
After=var-lib-ts\x2ddata.mount var-lib-ts\x2dorch.mount

[Service]
ExecStartPre=/bin/bash /usr/local/lib/ts-orch/data-mount-check.sh
UNIT
done
systemctl daemon-reload
`
