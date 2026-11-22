#!/usr/bin/env bash
set -euo pipefail
work=$1
data_loop=$(cat "$work/data-loop")
uuid=$(cat "$work/data-uuid")
truncate -s 32G "$work/data-volume.img"
losetup --set-capacity "$data_loop"
install -d -m 0755 /dev/oracleoci /usr/local/lib/ts-orch
ln -s "$data_loop" /dev/oracleoci/oraclevdb
PROBE_CAT=$(command -v cat)
export PROBE_CAT
export PATH="$work/probe-bin:$PATH"
bash "$work/data-volume.sh" false ocid1.volume.oc1.test.data "$uuid" 0123456789abcdef0123456789abcdef
install -m 0755 /dev/stdin /usr/local/lib/ts-orch/e2e-lsblk <<'PROBE'
#!/usr/bin/env bash
set -euo pipefail
test "$#" -eq 4
[[ $1 == -dnr && $2 == -o && $3 == SERIAL && -b $4 ]]
resolved=$(readlink -f "$4")
[[ $resolved == /dev/loop* ]]
test "$resolved" = "$(readlink -f /dev/oracleoci/oraclevdb)"
printf '%s\n' 0123456789abcdef0123456789abcdef
PROBE
install -d -m 0755 /usr/local/lib/ts-orch/e2e-device-bin
ln -s /usr/local/lib/ts-orch/e2e-lsblk /usr/local/lib/ts-orch/e2e-device-bin/lsblk
printf '[Service]\nEnvironment=PATH=/usr/local/lib/ts-orch/e2e-device-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n' > /etc/systemd/system/ts-orch.service.d/e2e-device.conf
sed -i "s|serial=\$(lsblk |serial=\$(/usr/local/lib/ts-orch/e2e-lsblk |" /usr/local/lib/ts-orch/data-mount-check.sh
