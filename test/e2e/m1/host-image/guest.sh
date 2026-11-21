#!/usr/bin/env bash
set -euo pipefail
exec >/dev/console 2>&1
case=$(cat /etc/host-image-case)
finish() {
 status=$?
 trap - EXIT
 lsblk -o PATH,TYPE,MODEL,SERIAL,WWN,FSTYPE,MOUNTPOINTS
 journalctl -b --no-pager -u ts-node-init.service -u ts-orch.service -u host-image-metadata.service
 if [[ $status -eq 0 ]]; then
  echo "host-image $case: PASS"
 else
  echo "host-image $case: FAIL ($status)"
 fi
 systemctl poweroff --no-block
 exit "$status"
}
trap finish EXIT
baked=$(cat /usr/local/lib/ts-orch/image-release.sha256)
installed=$(sha256sum /usr/local/bin/terrascale-orchestrator | cut -d' ' -f1)
if [[ $case == wrong-sha256 ]]; then
 systemctl is-failed --quiet ts-node-init.service
 test "$(systemctl show ts-node-init.service -p ExecMainStatus --value)" -ne 0
 active_at=$(systemctl show ts-orch.service -p ActiveEnterTimestampMonotonic --value)
 test "$active_at" = 0
 test "$installed" = "$baked"
 journalctl -b -u ts-node-init.service --no-pager | grep -F 'nothing installed'
 test "$(cat /opt/host-image/downloads)" = wrong-sha256
 test ! -e /etc/ts-orch/data-volume-uuid
 test ! -e /var/lib/ts-orch-bootstrap/format-consumed
 signatures=$(wipefs --no-act --noheadings --output TYPE /dev/oracleoci/oraclevdb)
 test -z "$signatures"
 exit 0
fi
systemctl is-active --quiet ts-node-init.service
test "$(systemctl show ts-node-init.service -p ExecMainStatus --value)" = 0
systemctl is-active --quiet ts-orch.service
test "$(blkid -p -s TYPE -o value /dev/oracleoci/oraclevdb)" = ext4
uuid=$(blkid -p -s UUID -o value /dev/oracleoci/oraclevdb)
test "$uuid" = "$(cat /etc/ts-orch/data-volume-uuid)"
test "$(findmnt -rn -M /var/lib/ts-data -o UUID)" = "$uuid"
test "$(findmnt -rn -M /var/lib/ts-orch -o FSROOT)" = /ts-orch
record=$(sha256sum /var/lib/ts-orch-bootstrap/format-consumed | cut -d' ' -f1)
if [[ $case == reboot ]]; then
 test "$uuid $record" = "$(cat /var/lib/ts-data/host-image-first-boot)"
 test "$(cat /var/lib/ts-data/host-image-payload)" = preserved-across-reboot
 echo "reboot: UUID=$uuid, format-consumed=$record and data unchanged"
else
 test -s /var/lib/ts-orch-bootstrap/format-consumed
 printf '%s %s\n' "$uuid" "$record" > /var/lib/ts-data/host-image-first-boot
 echo preserved-across-reboot > /var/lib/ts-data/host-image-payload
 echo "first bind: formatted and mounted UUID=$uuid"
fi
if [[ $case == late-bind ]]; then
 journalctl -b -u ts-node-init.service --no-pager | grep -F "waiting for the pool to bind this instance's data volume"
 journalctl -b -u ts-node-init.service --no-pager | grep -F 'instance metadata binds a data volume'
fi
if [[ $case == launch-release ]]; then
 test "$installed" = "$(cat /opt/host-image/launch.sha256)"
 test "$installed" != "$baked"
 test "$(cat /opt/host-image/downloads)" = launch-release
 journalctl -b -u ts-node-init.service --no-pager | grep -F "replaced the image's binary"
else
 test "$installed" = "$baked"
 test ! -e /opt/host-image/downloads
fi
systemd-analyze critical-chain ts-orch.service
systemctl show ts-orch.service -p ActiveEnterTimestamp -p ActiveEnterTimestampMonotonic
echo "BOOT-TIME $case $(systemctl show ts-orch.service -p ActiveEnterTimestampMonotonic --value) us; $(date -u +%FT%TZ)"
