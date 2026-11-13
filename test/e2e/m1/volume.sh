#!/usr/bin/env bash
set -euo pipefail
repo=$1
work=$2
go -C "$repo" run ./test/e2e/m1/region-volume
go -C "$repo" build -o "$work/data-mount-report" ./test/e2e/m1/data-mount
go -C "$repo" run ./test/e2e/m1/cloudinit > "$work/cloud-init.sh"
bash -n "$work/cloud-init.sh"
sed -n "/^echo .*base64 -d > \\/usr\\/local\\/lib\\/ts-orch\\/data-volume.sh/p" "$work/cloud-init.sh" | cut -d "'" -f2 | base64 -d > "$work/data-volume.sh"
bash -n "$work/data-volume.sh"
test "$(grep -n "^bash /usr/local/lib/ts-orch/data-volume.sh true 'data' ''$" "$work/cloud-init.sh" | cut -d: -f1)" -lt "$(grep -n '^systemctl restart ts-orch.service' "$work/cloud-init.sh" | cut -d: -f1)"
truncate -s 3G "$work/data-volume.img" "$work/expected.img"
data_loop=$(losetup --find --show "$work/data-volume.img")
loop_minor=$(stat -c %T "$data_loop")
loop_minor=$((16#$loop_minor))
stop_data_volume() {
 if [[ $(readlink /proc/self/ns/mnt) == $(readlink /proc/1/ns/mnt) ]]; then
  systemctl stop ts-orch.service netbird-server.service 2>/dev/null || true
 fi
 umount /var/lib/ts-orch 2>/dev/null || true
 umount /var/lib/ts-data 2>/dev/null || true
 rm -f /dev/oracleoci/oraclevdb
 losetup -d "$data_loop"
}
trap stop_data_volume EXIT
if [[ $(readlink /proc/self/ns/mnt) != $(readlink /proc/1/ns/mnt) ]]; then
mount --make-rprivate /
mount -t tmpfs tmpfs /var/lib
mount -t tmpfs tmpfs /etc
mount -t tmpfs tmpfs /usr/local/lib
mount -t tmpfs tmpfs /dev
mkdir -p /dev/oracleoci /var/lib/ts-orch /var/lib/ts-data /etc/systemd/system /usr/local/lib/ts-orch
touch /etc/fstab
mknod "$data_loop" b 7 "$loop_minor"
mknod /dev/null c 1 3
mknod /dev/zero c 1 5
mknod /dev/random c 1 8
mknod /dev/urandom c 1 9
ln -s /proc/self/fd /dev/fd
fi
install -d -m 0755 /dev/oracleoci
ln -s "$data_loop" /dev/oracleoci/oraclevdb
mkdir "$work/probe-bin"
cat > "$work/probe-bin/probe" <<'PROBE'
#!/usr/bin/env bash
set -euo pipefail
tool=$(basename "$0")
case "$tool:$*" in
 udevadm:*) probe=wait ;;
 curl:*volumeAttachments*) probe=binding-attachment ;;
 curl:*) probe=binding-instance ;;
 lsblk:*FSTYPE*) probe=lsblk-filesystems ;;
 lsblk:*TYPE*) probe=lsblk-types ;;
 lsblk:*PKNAME*) probe=lsblk-parent ;;
 lsblk:*MOUNTPOINT*) probe=lsblk-mounts ;;
 blkid:*-s\ TYPE*) probe=blkid-type ;;
 blkid:*-s\ UUID*) probe=blkid-uuid ;;
 blkid:*) probe=blkid ;;
 wipefs:*) probe=wipefs ;;
 blockdev:*) probe=blockdev ;;
 dd:*skip=0\ *) probe=read-first ;;
 dd:*skip=2147483648\ *) probe=read-last ;;
 dd:*skip=1073741824\ *) probe=read-middle ;;
 cmp:*) probe=compare ;;
 mkfs.ext4:*) touch "$PROBE_MARKER"; probe=format ;;
 systemctl:*) exit 0 ;;
 *) exit 90 ;;
esac
if [[ ${PROBE_FAIL:-} == "$probe-error" ]]; then touch "$PROBE_TRACE"; exit 70; fi
if [[ ${PROBE_FAIL:-} == "$probe-timeout" ]]; then touch "$PROBE_TRACE"; exit 124; fi
if [[ ${PROBE_FAIL:-} == "$probe-disagree" ]]; then
 touch "$PROBE_TRACE"
 case "$probe" in
  lsblk-types) echo part ;;
  lsblk-parent) echo boot ;;
  lsblk-mounts) echo / ;;
  lsblk-filesystems|wipefs) echo ext4 ;;
  blkid) exit 0 ;;
  blockdev) echo unknown ;;
  binding-instance) echo '{"id":"host","freeformTags":{"terrascale-data-volume":"other","terrascale-data-may-format":"yes"}}' ;;
  binding-attachment) echo '[{"instanceId":"host","volumeId":"adopted","device":"/dev/oracleoci/oraclevdb"}]' ;;
  read-first|read-last|read-middle) exit 0 ;;
  compare) exit 1 ;;
  *) exit 70 ;;
 esac
 exit 0
fi
case "$probe" in
 lsblk-types) test "$("$(cat "$0.path")" "$@")" = loop; echo disk; exit 0 ;;
 wait) exit 0 ;;
 binding-instance) echo '{"id":"host","freeformTags":{"terrascale-data-volume":"data","terrascale-data-may-format":"yes"}}'; exit 0 ;;
 binding-attachment) echo '[{"instanceId":"host","volumeId":"data","device":"/dev/oracleoci/oraclevdb"}]'; exit 0 ;;
esac
exec "$(cat "$0.path")" "$@"
PROBE
chmod +x "$work/probe-bin/probe"
for probe in udevadm curl lsblk blkid wipefs blockdev dd cmp mkfs.ext4 systemctl; do
 command -v "$probe" > "$work/probe-bin/$probe.path"
 ln -s probe "$work/probe-bin/$probe"
done
original_path=$PATH
export PATH="$work/probe-bin:$PATH"
export PROBE_MARKER="$work/format-attempted"
export PROBE_TRACE="$work/injected"
refuse() {
 local failure=$1 permission=$2 uuid=$3
 rm -f "$PROBE_TRACE"
 local -a before after
 read -r -a before < "/sys/class/block/${data_loop##*/}/stat"
 if PYTHONOPTIMIZE=1 PROBE_FAIL="$failure" bash "$work/data-volume.sh" "$permission" data "$uuid" >"$work/probe-$failure.log" 2>&1; then
  echo "accepted unsafe volume: $failure" >&2
  exit 1
 fi
 test ! -e "$PROBE_MARKER"
 case "$failure" in
  *-error|*-timeout|*-disagree) test -e "$PROBE_TRACE" ;;
 esac
 read -r -a after < "/sys/class/block/${data_loop##*/}/stat"
 test "${before[4]}:${before[6]}" = "${after[4]}:${after[6]}"
}
refuse adopted-empty false 11111111-1111-4111-8111-111111111111
refuse binding-attachment-disagree true ''
refuse binding-instance-disagree true ''
offset=$((1024 * 1024 * 1024 + 32 * 1024 * 1024))
printf x | "$(cat "$work/probe-bin/dd.path")" of="$data_loop" bs=1 seek="$offset" conv=notrunc status=none
printf x | "$(cat "$work/probe-bin/dd.path")" of="$work/expected.img" bs=1 seek="$offset" conv=notrunc status=none
refuse binding-attachment-disagree true ''
install -d -m 0700 /var/lib/ts-orch-bootstrap
printf consumed > /var/lib/ts-orch-bootstrap/format-consumed
refuse consumed-stale true ''
grep -q permission-consumed "$work/probe-consumed-stale.log"
rm /var/lib/ts-orch-bootstrap/format-consumed
printf '\0' | "$(cat "$work/probe-bin/dd.path")" of="$data_loop" bs=1 seek="$offset" conv=notrunc status=none
printf '\0' | "$(cat "$work/probe-bin/dd.path")" of="$work/expected.img" bs=1 seek="$offset" conv=notrunc status=none
for offset in 0 1073741824 3221225471; do
 printf x | "$(cat "$work/probe-bin/dd.path")" of="$data_loop" bs=1 seek="$offset" conv=notrunc status=none
 printf x | "$(cat "$work/probe-bin/dd.path")" of="$work/expected.img" bs=1 seek="$offset" conv=notrunc status=none
 refuse "raw-$offset" true ''
 printf '\0' | "$(cat "$work/probe-bin/dd.path")" of="$data_loop" bs=1 seek="$offset" conv=notrunc status=none
 printf '\0' | "$(cat "$work/probe-bin/dd.path")" of="$work/expected.img" bs=1 seek="$offset" conv=notrunc status=none
done
for probe in wait binding-instance binding-attachment lsblk-types lsblk-parent lsblk-mounts blockdev read-first read-last read-middle compare blkid wipefs lsblk-filesystems; do
 for outcome in error timeout disagree; do
  refuse "$probe-$outcome" true ''
 done
done
"$(cat "$work/probe-bin/cmp.path")" "$data_loop" "$work/expected.img"
echo "data volume: every probe error, timeout and disagreement, unreadable first GiB and short reads refuse; disk bytes unchanged"
install -d -m 0755 /usr/local/lib/ts-orch
bash "$work/data-volume.sh" true data ''
test -e "$PROBE_MARKER"
grep -q "^size=3221225472$" /var/lib/ts-orch-bootstrap/format-consumed
grep -Eq "^time=[0-9]{4}-" /var/lib/ts-orch-bootstrap/format-consumed
rm "$PROBE_MARKER"
uuid=$("$(cat "$work/probe-bin/blkid.path")" -s UUID -o value "$data_loop")
touch /var/lib/ts-data/terrabase/kept /var/lib/ts-orch/identity-kept
bash /usr/local/lib/ts-orch/data-mount-check.sh
"$work/data-mount-report" > "$work/mount-report.json"
python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); assert r["mount_point"]=="/var/lib/ts-data" and r["device"]=="/dev/oracleoci/oraclevdb" and r["uuid"]==sys.argv[2] and r["filesystem_type"]=="ext4" and r["size_bytes"]==3221225472' "$work/mount-report.json" "$uuid"
printf '%s\n' 22222222-2222-4222-8222-222222222222 > /etc/ts-orch/data-volume-uuid
if bash /usr/local/lib/ts-orch/data-mount-check.sh; then exit 1; fi
printf '%s\n' "$uuid" > /etc/ts-orch/data-volume-uuid
umount /var/lib/ts-orch /var/lib/ts-data
cp --reflink=auto --sparse=always "$work/data-volume.img" "$work/expected.img"
refuse second-first-boot true ''
refuse stale-permission true ''
for probe in blkid-type blkid-uuid; do
 for outcome in error timeout disagree; do
  refuse "$probe-$outcome" false "$uuid"
 done
done
if "$work/data-mount-report" >"$work/no-mount.log" 2>&1; then exit 1; fi
"$(cat "$work/probe-bin/cmp.path")" "$data_loop" "$work/expected.img"
bash "$work/data-volume.sh" false data "$uuid"
test "$("$(cat "$work/probe-bin/blkid.path")" -s UUID -o value "$data_loop")" = "$uuid"
test -f /var/lib/ts-data/terrabase/kept
test -f /var/lib/ts-orch/identity-kept
cmp /etc/systemd/system/ts-orch.service.d/data-volume.conf /etc/systemd/system/netbird-server.service.d/data-volume.conf
echo "data volume: format once; consumed stale permission and second first boot refuse unchanged; adoption preserves UUID, data and identity"
echo "data volume: real mount report verified; unmounted host and UUID service precondition refuse"
export PATH="$original_path"
