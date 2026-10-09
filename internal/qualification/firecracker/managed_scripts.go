package firecracker

import "strings"

const managedVolumeSetupScriptA = `#!/bin/sh
set -eu
DEVICE=/dev/vdb
ALIAS=/dev/oracleoci/oraclevdb
MOUNT=__MANAGED_MEMBER_DIR__/volume
UUID=76f1b43d-7d79-4f41-9a6e-cc1f4aaab102
attempt=0
while [ "$attempt" -lt 120 ]; do
  if [ -b "$DEVICE" ] && [ -e "/dev/disk/by-uuid/$UUID" ] &&
     [ "$(readlink -f "/dev/disk/by-uuid/$UUID")" = "$DEVICE" ]; then break; fi
  attempt=$((attempt + 1)); sleep 0.5
done
[ "$attempt" -lt 120 ] || exit 1
[ "$(/usr/sbin/blkid -s UUID -o value "$DEVICE")" = "$UUID" ] || exit 1
for directory in /srv/ts-managed __MANAGED_MEMBER_DIR__ __MANAGED_MEMBER_DIR__/material __MANAGED_MEMBER_DIR__/control "$MOUNT"; do
  [ ! -L "$directory" ] && [ -d "$directory" ] || exit 1
done
[ ! -e /dev/oracleoci ] || [ -d /dev/oracleoci ] || exit 1
mkdir -p /dev/oracleoci
[ ! -e "$ALIAS" ] && [ ! -L "$ALIAS" ] || exit 1
ln -s ../vdb "$ALIAS"
if findmnt -rn -S "$DEVICE" >/dev/null 2>&1 || mountpoint -q "$MOUNT"; then exit 1; fi
mount -t ext4 -o rw "$ALIAS" "$MOUNT"
[ "$(findmnt -n -o TARGET --source "$DEVICE")" = "$MOUNT" ] || exit 1
[ "$(findmnt -n -o FSTYPE --target "$MOUNT")" = ext4 ] || exit 1
chown 0:65534 "$MOUNT"; chmod 0750 "$MOUNT"
[ ! -e "$MOUNT/.terrascale-member-claim" ] || exit 1
mkdir -m 0700 "$MOUNT/data" "$MOUNT/replication"
chown 65534:65534 "$MOUNT/data" "$MOUNT/replication"
`

const managedRunnerScriptA = `#!/bin/sh
set -u
LOG=/var/log/ts-managed-member/go-host-test.log
mkdir -p /var/log/ts-managed-member
attempt=0
while [ "$attempt" -lt 120 ]; do
  if ip -4 -o addr show | grep -Fq '10.77.39.11/24'; then break; fi
  attempt=$((attempt + 1)); sleep 0.5
done
if [ "$attempt" -ge 120 ]; then
  echo 'TS_MANAGED_MEMBER_QUALIFICATION_RESULT=FAILED status=90'
  systemctl --no-block reboot || true
  exit 90
fi
TS_FC_MANAGED_MEMBER_CONFIG=/etc/ts-managed-member/guest-config.json \
TS_FC_MANAGED_S3_ACCESS_KEY_FILE=/etc/ts-managed-member/s3-access-key-id \
TS_FC_MANAGED_S3_SECRET_KEY_FILE=/etc/ts-managed-member/s3-secret-access-key \
  /opt/ts-managed-member/host.test -test.run='^TestManagedMemberFirecrackerSignedServing$' -test.v -test.timeout=480s > "$LOG" 2>&1
status=$?
cat "$LOG"
if [ "$status" -eq 0 ]; then
  echo 'TS_MANAGED_MEMBER_QUALIFICATION_RESULT=PASS node=node-a'
else
  echo 'TS_MANAGED_MEMBER_QUALIFICATION_RESULT=FAILED status='"$status"
fi
sync
systemctl --no-block reboot || true
exit "$status"
`

const managedVolumeSetupScriptB = `#!/bin/sh
set -eu
DEVICE=/dev/vdb
ALIAS=/dev/oracleoci/oraclevdb
MOUNT=__MANAGED_MEMBER_DIR__/volume
UUID=76f1b43d-7d79-4f41-9a6e-cc1f4aaab103
attempt=0
while [ "$attempt" -lt 120 ]; do
  if [ -b "$DEVICE" ] && [ -e "/dev/disk/by-uuid/$UUID" ] &&
     [ "$(readlink -f "/dev/disk/by-uuid/$UUID")" = "$DEVICE" ]; then break; fi
  attempt=$((attempt + 1)); sleep 0.5
done
[ "$attempt" -lt 120 ] || exit 1
[ "$(/usr/sbin/blkid -s UUID -o value "$DEVICE")" = "$UUID" ] || exit 1
for directory in /srv/ts-managed __MANAGED_MEMBER_DIR__ __MANAGED_MEMBER_DIR__/material __MANAGED_MEMBER_DIR__/control "$MOUNT"; do
  [ ! -L "$directory" ] && [ -d "$directory" ] || exit 1
done
[ ! -e /dev/oracleoci ] || [ -d /dev/oracleoci ] || exit 1
mkdir -p /dev/oracleoci
[ ! -e "$ALIAS" ] && [ ! -L "$ALIAS" ] || exit 1
ln -s ../vdb "$ALIAS"
if findmnt -rn -S "$DEVICE" >/dev/null 2>&1 || mountpoint -q "$MOUNT"; then exit 1; fi
mount -t ext4 -o rw "$ALIAS" "$MOUNT"
[ "$(findmnt -n -o TARGET --source "$DEVICE")" = "$MOUNT" ] || exit 1
[ "$(findmnt -n -o FSTYPE --target "$MOUNT")" = ext4 ] || exit 1
chown 0:65534 "$MOUNT"; chmod 0750 "$MOUNT"
[ ! -e "$MOUNT/.terrascale-member-claim" ] || exit 1
mkdir -m 0700 "$MOUNT/data" "$MOUNT/replication"
chown 65534:65534 "$MOUNT/data" "$MOUNT/replication"
`

const managedRunnerScriptB = `#!/bin/sh
set -u
LOG=/var/log/ts-managed-member/go-host-test.log
mkdir -p /var/log/ts-managed-member
attempt=0
while [ "$attempt" -lt 120 ]; do
  if ip -4 -o addr show | grep -Fq '10.77.39.12/24'; then break; fi
  attempt=$((attempt + 1)); sleep 0.5
done
if [ "$attempt" -ge 120 ]; then
  echo 'TS_MANAGED_MEMBER_QUALIFICATION_RESULT=FAILED status=90'
  systemctl --no-block reboot || true
  exit 90
fi
TS_FC_MANAGED_MEMBER_CONFIG=/etc/ts-managed-member/guest-config.json \
TS_FC_MANAGED_S3_ACCESS_KEY_FILE=/etc/ts-managed-member/s3-access-key-id \
TS_FC_MANAGED_S3_SECRET_KEY_FILE=/etc/ts-managed-member/s3-secret-access-key \
  /opt/ts-managed-member/host.test -test.run='^TestManagedMemberFirecrackerSignedServing$' -test.v -test.timeout=480s > "$LOG" 2>&1
status=$?
cat "$LOG"
if [ "$status" -eq 0 ]; then
  echo 'TS_MANAGED_MEMBER_QUALIFICATION_RESULT=PASS node=node-b'
else
  echo 'TS_MANAGED_MEMBER_QUALIFICATION_RESULT=FAILED status='"$status"
fi
sync
systemctl --no-block reboot || true
exit "$status"
`

const ManagedSetupUnit = `[Unit]
Description=Prepare pinned managed member volume
After=local-fs.target
Before=ts-managed-member-test.service

[Service]
Type=oneshot
User=root
TimeoutStartSec=90s
ExecStart=/usr/local/sbin/ts-managed-member-volume-setup
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`

const ManagedTestUnit = `[Unit]
Description=Two-VM managed member qualification
After=network-online.target ts-managed-member-volume-setup.service
Requires=ts-managed-member-volume-setup.service
Wants=network-online.target

[Service]
Type=oneshot
Delegate=yes
DelegateSubgroup=supervisor
MemoryMax=5G
MemoryMin=1G
MemoryLow=1G
CPUWeight=10000
IOWeight=10000
Nice=-20
OOMScoreAdjust=-1000
ManagedOOMPreference=omit
IOSchedulingClass=best-effort
IOSchedulingPriority=0
NoNewPrivileges=yes
AmbientCapabilities=
CapabilityBoundingSet=CAP_CHOWN CAP_KILL CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_DAC_READ_SEARCH
TimeoutStartSec=510s
KillMode=control-group
StandardOutput=journal+console
StandardError=journal+console
ExecStart=/usr/local/sbin/ts-managed-member-runner

[Install]
WantedBy=multi-user.target
`

const ManagedSystemSliceReservation = `[Slice]
MemoryMin=1G
MemoryLow=1G
`

func ManagedVolumeSetupScript(member string) string {
	if member == "b" {
		return strings.ReplaceAll(managedVolumeSetupScriptB, "__MANAGED_MEMBER_DIR__", ManagedMemberDirs["b"])
	}
	return strings.ReplaceAll(managedVolumeSetupScriptA, "__MANAGED_MEMBER_DIR__", ManagedMemberDirs["a"])
}
func ManagedRunnerScript(member string) string {
	if member == "b" {
		return managedRunnerScriptB
	}
	return managedRunnerScriptA
}
