#!/usr/bin/env bash
set -euo pipefail
repo=$1
work=$2
binaries=$3
"$binaries/region-volume"
"$binaries/cloudinit" > "$work/cloud-init.sh"
bash -n "$work/cloud-init.sh"
sed -n "/^echo .*base64 -d > \\/usr\\/local\\/lib\\/ts-orch\\/data-volume.sh/p" "$work/cloud-init.sh" | cut -d "'" -f2 | base64 -d > "$work/data-volume.sh"
bash -n "$work/data-volume.sh"
test "$(grep -n "^bash /usr/local/lib/ts-orch/data-volume.sh true 'ocid1.volume.oc1.test.data' '' ''$" "$work/cloud-init.sh" | cut -d: -f1)" -lt "$(grep -n '^systemctl restart ts-orch.service' "$work/cloud-init.sh" | cut -d: -f1)"
truncate -s 3G "$work/data-volume.img" "$work/expected.img"
data_loop=$(losetup --find --show "$work/data-volume.img")
loop_minor=$(stat -c %T "$data_loop")
loop_minor=$((16#$loop_minor))
metadata_pid=""
stop_data_volume() {
 if test -n "$metadata_pid"; then kill "$metadata_pid" 2>/dev/null || true; wait "$metadata_pid" 2>/dev/null || true; fi
 if [[ $(readlink /proc/self/ns/mnt) == $(readlink /proc/1/ns/mnt) ]]; then
  systemctl stop ts-orch.service netbird-server.service 2>/dev/null || true
 fi
 umount /var/lib/ts-orch 2>/dev/null || true
 umount /var/lib/ts-data 2>/dev/null || true
 rm -f /dev/oracleoci/oraclevdb
 losetup -d "$data_loop"
 if test -n "${replacement_loop:-}"; then losetup -d "$replacement_loop"; fi
}
trap stop_data_volume EXIT
truncate -s 1G "$work/replacement.img"
replacement_loop=$(losetup --find --show "$work/replacement.img")
replacement_minor=$(stat -c %T "$replacement_loop")
if [[ $(readlink /proc/self/ns/mnt) != $(readlink /proc/1/ns/mnt) ]]; then
mount --make-rprivate /
mount -t tmpfs tmpfs /var/lib
mount -t tmpfs tmpfs /etc
mount -t tmpfs tmpfs /usr/local/lib
mount -t tmpfs tmpfs /dev
mkdir -p /dev/oracleoci /var/lib/ts-orch /var/lib/ts-data /etc/systemd/system /usr/local/lib/ts-orch
touch /etc/fstab
mknod "$data_loop" b 7 "$loop_minor"
mknod "$replacement_loop" b 7 "$((16#$replacement_minor))"
mknod /dev/null c 1 3
mknod /dev/zero c 1 5
mknod /dev/random c 1 8
mknod /dev/urandom c 1 9
ln -s /proc/self/fd /dev/fd
fi
install -d -m 0755 /dev/oracleoci
ln -s "$data_loop" /dev/oracleoci/oraclevdb
mkfifo "$work/metadata-ready"
python3 "$repo/test/e2e/m1/volume-metadata.py" "$work/metadata-ready" >"$work/metadata.log" 2>&1 &
metadata_pid=$!
exec {metadata_ready}<>"$work/metadata-ready"
read -r -t 10 -u "$metadata_ready" metadata_port
exec {metadata_ready}>&-
export METADATA_PORT="$metadata_port"
curl -fsS --noproxy '*' "http://127.0.0.1:$metadata_port/opc/v2/instance/" > "$work/instance.json"
test "$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' "http://127.0.0.1:$metadata_port/opc/v2/volumeAttachments/")" = 404
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert "freeformTags" not in d and isinstance(d["id"],str) and isinstance(d["metadata"],dict) and len(d)==19' "$work/instance.json"
mkdir "$work/probe-bin"
cat > "$work/probe-bin/probe" <<'PROBE'
#!/usr/bin/env bash
set -euo pipefail
tool=$(basename "$0")
case "$tool:$*" in
 udevadm:*) probe=wait ;;
 curl:*) probe=binding-instance ;;
 mountpoint:*|findmnt:*|cat:*|readlink:*)
  if [[ ${CHECK_FAIL:-} == "$tool:$*" ]]; then touch "$CHECK_TRACE"; exit 71; fi
  if [[ ${CHECK_EMPTY:-} == "$tool:$*" ]]; then touch "$CHECK_TRACE"; exit 0; fi
  exec "$("$PROBE_CAT" "$0.path")" "$@" ;;
 lsblk:*MODEL*) probe=disk-model ;;
 lsblk:*SERIAL*) probe=disk-serial ;;
 lsblk:*WWN*) probe=disk-wwn ;;
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
if [[ ${CHECK_FAIL:-} == "$tool:$*" ]]; then touch "$CHECK_TRACE"; exit 71; fi
if [[ ${CHECK_EMPTY:-} == "$tool:$*" ]]; then touch "$CHECK_TRACE"; exit 0; fi
if [[ ${PROBE_FAIL:-} == "$probe-error" ]]; then touch "$PROBE_TRACE"; exit 70; fi
if [[ ${PROBE_FAIL:-} == "$probe-timeout" ]]; then touch "$PROBE_TRACE"; exit 124; fi
if [[ ${PROBE_FAIL:-} == "$probe-disagree" ]]; then
 touch "$PROBE_TRACE"
 case "$probe" in
  lsblk-types) echo part ;;
  disk-model) echo BootVolume ;;
  disk-serial) echo invalid ;;
  disk-wwn) echo 0x00000000000000000000000000000000 ;;
  lsblk-parent) echo boot ;;
  lsblk-mounts) echo / ;;
  lsblk-filesystems|wipefs) echo ext4 ;;
  blkid) exit 0 ;;
  blockdev) echo unknown ;;
  binding-instance) echo '{"id":"host","metadata":{"terrascale-data-volume":"ocid1.volume.oc1.test.other","terrascale-data-may-format":"true"}}' ;;

  read-first|read-last|read-middle) exit 0 ;;
  compare) exit 1 ;;
  *) exit 70 ;;
 esac
 exit 0
fi
case "$probe" in
 format) exec "$("$PROBE_CAT" "$0.path")" -E lazy_itable_init=0,lazy_journal_init=0 "$@" ;;
 lsblk-types) test "$("$("$PROBE_CAT" "$0.path")" "$@")" = loop; echo disk; exit 0 ;;
 wait) exit 0 ;;
 disk-model) echo BlockVolume; exit 0 ;;
 disk-serial)
  if test -n "${GROW_REPLACEMENT:-}"; then ln -sfn "$GROW_REPLACEMENT" /dev/oracleoci/oraclevdb; fi
  echo 0123456789abcdef0123456789abcdef
  exit 0 ;;
 disk-wwn) echo 0x0123456789abcdef0123456789abcdef; exit 0 ;;
 binding-instance)
  args=()
  for arg in "$@"; do
   if [[ $arg == http://169.254.169.254/* ]]; then
    if [[ ${PROBE_FAIL:-} == metadata-unreachable ]]; then
     arg=http://127.0.0.1:1/opc/v2/instance/
    else
     arg="http://127.0.0.1:$METADATA_PORT/opc/v2/instance/"
    fi
   fi
   args+=("$arg")
  done
  exec "$("$PROBE_CAT" "$0.path")" --noproxy '*' -H "X-Lane-Case: ${PROBE_FAIL:-}" "${args[@]}" ;;
esac
exec "$("$PROBE_CAT" "$0.path")" "$@"
PROBE
chmod +x "$work/probe-bin/probe"
for probe in udevadm curl lsblk blkid wipefs blockdev dd cmp mkfs.ext4 systemctl mountpoint findmnt cat readlink; do
 command -v "$probe" > "$work/probe-bin/$probe.path"
 ln -s probe "$work/probe-bin/$probe"
done
export PROBE_CAT="$(command -v cat)"
original_path=$PATH
export PATH="$work/probe-bin:$PATH"
export PROBE_MARKER="$work/format-attempted"
export PROBE_TRACE="$work/injected"
refuse() {
 local failure=$1 permission=$2 uuid=$3 serial=${4:-}
 rm -f "$PROBE_TRACE"
 local -a before after
 read -r -a before < "/sys/class/block/${data_loop##*/}/stat"
 if PYTHONOPTIMIZE=1 PROBE_FAIL="$failure" bash "$work/data-volume.sh" "$permission" ocid1.volume.oc1.test.data "$uuid" "$serial" >"$work/probe-$failure.log" 2>&1; then
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
for failure in instance-id-null instance-id-empty instance-id-number instance-id-missing instance-invalid-json metadata-missing metadata-null metadata-array metadata-unreachable metadata-stalled; do
 refuse "$failure" true ''
done
grep -q 'Operation timed out' "$work/probe-metadata-stalled.log"
grep -q 'Failed to connect' "$work/probe-metadata-unreachable.log"
for key in volume permission; do
 for value in missing empty different null malformed; do
  refuse "binding-$key-$value" true ''
 done
done
refuse binding-volume-number true ''
refuse binding-permission-boolean true ''
echo "data volume: real metadata schema, attachment 404, invalid identities and bindings, unreachable and stalled HTTP refuse with zero disk writes"
refuse adopted-empty false 11111111-1111-4111-8111-111111111111
refuse binding-volume-different true ''
refuse binding-instance-disagree true ''
offset=$((1024 * 1024 * 1024 + 32 * 1024 * 1024))
printf x | "$(cat "$work/probe-bin/dd.path")" of="$data_loop" bs=1 seek="$offset" conv=notrunc status=none
printf x | "$(cat "$work/probe-bin/dd.path")" of="$work/expected.img" bs=1 seek="$offset" conv=notrunc status=none
refuse binding-volume-different true ''
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
for probe in wait binding-instance lsblk-types disk-model disk-serial disk-wwn lsblk-parent lsblk-mounts blockdev read-first read-last read-middle compare blkid wipefs lsblk-filesystems; do
 for outcome in error timeout disagree; do
  refuse "$probe-$outcome" true ''
 done
done
"$(cat "$work/probe-bin/cmp.path")" "$data_loop" "$work/expected.img"
echo "data volume: every probe error, timeout and disagreement, unreadable first GiB and short reads refuse; disk bytes unchanged"
install -d -m 0755 /usr/local/lib/ts-orch
bash "$work/data-volume.sh" true ocid1.volume.oc1.test.data '' ''
test -e "$PROBE_MARKER"
grep -q "^serial=0123456789abcdef0123456789abcdef$" /var/lib/ts-orch-bootstrap/format-consumed
grep -q "^size=3221225472$" /var/lib/ts-orch-bootstrap/format-consumed
grep -Eq "^time=[0-9]{4}-" /var/lib/ts-orch-bootstrap/format-consumed
rm "$PROBE_MARKER"
uuid=$("$(cat "$work/probe-bin/blkid.path")" -s UUID -o value "$data_loop")
touch /var/lib/ts-data/terrabase/kept /var/lib/ts-orch/identity-kept
bash /usr/local/lib/ts-orch/data-mount-check.sh
"$binaries/data-mount" > "$work/mount-report.json"
python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); assert r["mount_point"]=="/var/lib/ts-data" and r["device"]=="/dev/oracleoci/oraclevdb" and r["uuid"]==sys.argv[2] and r["filesystem_type"]=="ext4" and r["size_bytes"]==3221225472 and r["serial"]=="0123456789abcdef0123456789abcdef"' "$work/mount-report.json" "$uuid"
printf 'retained database bytes\n' > /var/lib/ts-data/terrabase/kept
before_growth=$(stat -f -c %b /var/lib/ts-data)
truncate -s 4G "$work/data-volume.img"
losetup --set-capacity "$data_loop"
printf '%s\n' 22222222-2222-4222-8222-222222222222 > /etc/ts-orch/data-volume-uuid
if "$binaries/data-mount" grow; then exit 1; fi
printf '%s\n' "$uuid" > /etc/ts-orch/data-volume-uuid
printf '%s\n' fedcba9876543210fedcba9876543210 > /etc/ts-orch/data-volume-serial
if "$binaries/data-mount" grow; then exit 1; fi
printf '%s\n' 0123456789abcdef0123456789abcdef > /etc/ts-orch/data-volume-serial
test "$(stat -f -c %b /var/lib/ts-data)" = "$before_growth"
"$(cat "$work/probe-bin/mkfs.ext4.path")" -q "$replacement_loop"
replacement_before=$(sha256sum "$replacement_loop" | cut -d' ' -f1)
GROW_REPLACEMENT="$replacement_loop" "$binaries/data-mount" grow
test "$(readlink -f /dev/oracleoci/oraclevdb)" = "$replacement_loop"
test "$(sha256sum "$replacement_loop" | cut -d' ' -f1)" = "$replacement_before"
ln -sfn "$data_loop" /dev/oracleoci/oraclevdb
losetup -d "$replacement_loop"
replacement_loop=""
after_growth=$(stat -f -c %b /var/lib/ts-data)
test "$after_growth" -gt "$before_growth"
test "$(cat /var/lib/ts-data/terrabase/kept)" = 'retained database bytes'
test "$(findmnt -rn -M /var/lib/ts-data -o UUID)" = "$uuid"
"$binaries/data-mount" grow
test "$(stat -f -c %b /var/lib/ts-data)" = "$after_growth"
echo "data volume: UUID/serial mismatch refuses; an alias swap preserves the replacement device; online growth preserves bytes and UUID and is idempotent"
printf '%s\n' 22222222-2222-4222-8222-222222222222 > /etc/ts-orch/data-volume-uuid
if bash /usr/local/lib/ts-orch/data-mount-check.sh; then exit 1; fi
printf '%s\n' "$uuid" > /etc/ts-orch/data-volume-uuid
sync -f /var/lib/ts-data
export CHECK_TRACE="$work/check-injected"
for command in \
 'mountpoint:-q /var/lib/ts-data' \
 'mountpoint:-q /var/lib/ts-orch' \
 'findmnt:-rn -M /var/lib/ts-data -o UUID' \
 'cat:/etc/ts-orch/data-volume-uuid' \
 'findmnt:-rn -M /var/lib/ts-data -o SOURCE' \
 "readlink:-f $data_loop" \
 'readlink:-f /dev/oracleoci/oraclevdb' \
 "lsblk:-dnr -o SERIAL $data_loop" \
 'cat:/etc/ts-orch/data-volume-serial' \
 'findmnt:-rn -M /var/lib/ts-data -o MAJ:MIN' \
 'findmnt:-rn -M /var/lib/ts-orch -o MAJ:MIN' \
 'findmnt:-rn -M /var/lib/ts-data -o FSROOT' \
 'findmnt:-rn -M /var/lib/ts-orch -o FSROOT'; do
 for outcome in fail empty; do
  [[ $command != mountpoint:* || $outcome != empty ]] || continue
  rm -f "$CHECK_TRACE"
  read -r -a before < "/sys/class/block/${data_loop##*/}/stat"
  if [[ $outcome == fail ]]; then
   if CHECK_FAIL="$command" bash /usr/local/lib/ts-orch/data-mount-check.sh; then exit 1; fi
  else
   if CHECK_EMPTY="$command" bash /usr/local/lib/ts-orch/data-mount-check.sh; then exit 1; fi
  fi
  test -e "$CHECK_TRACE"
  read -r -a after < "/sys/class/block/${data_loop##*/}/stat"
  test "${before[4]}:${before[6]}" = "${after[4]}:${after[6]}"
 done
done
umount /var/lib/ts-orch
mount --bind /var/lib/ts-data/terrabase /var/lib/ts-orch
read -r -a before < "/sys/class/block/${data_loop##*/}/stat"
if bash /usr/local/lib/ts-orch/data-mount-check.sh; then exit 1; fi
read -r -a after < "/sys/class/block/${data_loop##*/}/stat"
test "${before[4]}:${before[6]}" = "${after[4]}:${after[6]}"
echo "data volume: every checker command failure and empty result, and wrong second bind source refuse with zero disk writes"
umount /var/lib/ts-orch /var/lib/ts-data
cp --reflink=auto --sparse=always "$work/data-volume.img" "$work/expected.img"
refuse second-first-boot true ''
refuse stale-permission true ''
for probe in blkid-type blkid-uuid; do
 for outcome in error timeout disagree; do
  refuse "$probe-$outcome" false "$uuid"
 done
done
refuse adoption-serial-mismatch false "$uuid" fedcba9876543210fedcba9876543210
grep -q expected-serial "$work/probe-adoption-serial-mismatch.log"
if "$binaries/data-mount" >"$work/no-mount.log" 2>&1; then exit 1; fi
"$(cat "$work/probe-bin/cmp.path")" "$data_loop" "$work/expected.img"
bash "$work/data-volume.sh" false ocid1.volume.oc1.test.data "$uuid" 0123456789abcdef0123456789abcdef
test "$("$(cat "$work/probe-bin/blkid.path")" -s UUID -o value "$data_loop")" = "$uuid"
test -f /var/lib/ts-data/terrabase/kept
test -f /var/lib/ts-orch/identity-kept
cmp /etc/systemd/system/ts-orch.service.d/data-volume.conf /etc/systemd/system/netbird-server.service.d/data-volume.conf
echo "data volume: format once; consumed stale permission and second first boot refuse unchanged; adoption preserves UUID, data and identity"
echo "data volume: real mount report and serial verified; adoption serial mismatch refuses with zero disk writes; unmounted host and UUID service precondition refuse"
rm -f /etc/ts-orch/data-volume-uuid /etc/ts-orch/data-volume-serial
printf 'terrascale-orchestrator baked image release\n' > "$work/binary-baked"
printf 'terrascale-orchestrator launch release\n' > "$work/launch-release"
printf 'terrascale-orchestrator pushed release\n' > "$work/binary-pushed"
baked_sum=$(sha256sum "$work/binary-baked" | cut -d' ' -f1)
launch_sum=$(sha256sum "$work/launch-release" | cut -d' ' -f1)
pushed_sum=$(sha256sum "$work/binary-pushed" | cut -d' ' -f1)
nodeinit_cleanup() {
 kill ${release_pid:-} ${nodeinit_metadata_pid:-} 2>/dev/null || true
 wait ${release_pid:-} ${nodeinit_metadata_pid:-} 2>/dev/null || true
 ip addr del 169.254.169.254/32 dev lo 2>/dev/null || true
}
trap 'stop_data_volume; nodeinit_cleanup' EXIT
cat > "$work/nodeinit-release.py" <<'PY'
import http.server, ssl, sys
class Release(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_GET(self):
        if self.path != "/launch-release":
            self.send_error(404)
            return
        body = open(sys.argv[1], "rb").read()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
server = http.server.ThreadingHTTPServer(("127.0.0.1", 8443), Release)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[2], sys.argv[3])
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY
python3 "$work/nodeinit-release.py" "$work/launch-release" "$work/localhost.pem" "$work/localhost.key" >"$work/nodeinit-release.log" 2>&1 &
release_pid=$!
cat > "$work/nodeinit-metadata.py" <<'PY'
import http.server, json, sys
class Metadata(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_GET(self):
        if self.path != "/opc/v2/instance/metadata/":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({
            "terrascale-release-url": "https://127.0.0.1:8443/launch-release",
            "terrascale-release-sha256": sys.argv[1],
            "terrascale-data-volume": "ocid1.volume.oc1.test.data",
            "terrascale-data-may-format": "false",
            "terrascale-data-uuid": sys.argv[2],
        }).encode())
server = http.server.ThreadingHTTPServer(("169.254.169.254", 80), Metadata)
with open(sys.argv[3], "w") as ready:
    ready.write("ready\n")
server.serve_forever()
PY
ip addr replace 169.254.169.254/32 dev lo
mkfifo "$work/nodeinit-ready"
python3 "$work/nodeinit-metadata.py" "$launch_sum" "$uuid" "$work/nodeinit-ready" >"$work/nodeinit-metadata.log" 2>&1 &
nodeinit_metadata_pid=$!
exec {nodeinit_ready}<>"$work/nodeinit-ready"
read -r -t 10 -u "$nodeinit_ready" nodeinit_ready_line
exec {nodeinit_ready}>&-
nodeinit_drill() {
 local binary=$1 marker=$2 log=$3 mode=$4 expected_sum=$5 pattern=$6
 unshare --mount --fork bash -c '
  set -euo pipefail
  umount /var/lib/ts-orch /var/lib/ts-data 2>/dev/null || true
  mount -t tmpfs tmpfs /usr/local/bin
  install -m 0755 "$1" /usr/local/bin/terrascale-orchestrator
  printf "%s\n" "$2" > /usr/local/lib/ts-orch/image-release.sha256
  export SSL_CERT_FILE="$3" NO_PROXY="*" no_proxy="*"
  if "$4" node-init > "$5" 2>&1; then
   ran=0
  else
   ran=$?
  fi
  sed -i "s|serial=\$(lsblk |serial=\$("$8"/probe-bin/lsblk |" /usr/local/lib/ts-orch/data-mount-check.sh
  if test "$6" = keep; then
   test "$ran" = 0
   test "$(sha256sum /usr/local/bin/terrascale-orchestrator | cut -d" " -f1)" = "$7"
   mountpoint -q /var/lib/ts-data
   mountpoint -q /var/lib/ts-orch
   test -f /var/lib/ts-data/terrabase/kept
   bash /usr/local/lib/ts-orch/data-mount-check.sh
  else
   test "$ran" != 0
   test "$(sha256sum /usr/local/bin/terrascale-orchestrator | cut -d" " -f1)" = "$7"
   if mountpoint -q /var/lib/ts-data; then exit 1; fi
  fi
  grep -q "$9" "$5"
 ' bash "$binary" "$marker" "$work/ca.pem" "$binaries/terrascale-orchestrator" "$log" "$mode" "$expected_sum" "$work" "$pattern"
}
nodeinit_drill "$work/binary-baked" "$baked_sum" "$work/nodeinit-first.log" keep "$launch_sum" "replaced the image's binary sha256 $baked_sum with launch release $launch_sum"
install -d -m 0755 /var/lib/ts-orch/nats
printf '{"sha256":["%s"]}\n' "$baked_sum" > /var/lib/ts-orch/nats/release-installed
nodeinit_drill "$work/binary-baked" "$baked_sum" "$work/nodeinit-rebind.log" keep "$baked_sum" "has sha256 $baked_sum, not launch release $launch_sum"
nodeinit_drill "$work/binary-pushed" "$baked_sum" "$work/nodeinit-foreign.log" refuse "$pushed_sum" "neither the launch release nor the self-update record"
rm -f /etc/ts-orch/data-volume-uuid /etc/ts-orch/data-volume-serial
nodeinit_drill "$work/binary-pushed" "$baked_sum" "$work/nodeinit-unbound.log" refuse "$pushed_sum" "nothing is bound or formatted"
nodeinit_cleanup
echo "node-init: first bind replaces the baked image binary with the launch release and mounts the volume; a recorded rebind keeps the baked binary; a foreign digest refuses with and without records"
sed -i "s|serial=\$(lsblk |serial=\$($work/probe-bin/lsblk |" /usr/local/lib/ts-orch/data-mount-check.sh
export PATH="$original_path"
kill "$metadata_pid"
wait "$metadata_pid" 2>/dev/null || true
umount /var/lib/ts-orch /var/lib/ts-data
printf '%s\n' "$uuid" > "$work/data-uuid"
printf '%s\n' "$data_loop" > "$work/data-loop"
trap - EXIT
