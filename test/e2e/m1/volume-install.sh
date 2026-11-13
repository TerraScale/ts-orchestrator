#!/usr/bin/env bash
set -euo pipefail
work=$1
data_loop=$(cat "$work/data-loop")
uuid=$(cat "$work/data-uuid")
install -d -m 0755 /dev/oracleoci /usr/local/lib/ts-orch
ln -s "$data_loop" /dev/oracleoci/oraclevdb
export PROBE_CAT="$(command -v cat)"
export PATH="$work/probe-bin:$PATH"
bash "$work/data-volume.sh" false ocid1.volume.oc1.test.data "$uuid" 0123456789abcdef0123456789abcdef
install -m 0755 /dev/stdin /usr/local/lib/ts-orch/e2e-lsblk <<'PROBE'
#!/usr/bin/env bash
set -euo pipefail
test "$#" -eq 4
[[ $1 == -dnr && $2 == -o && $3 == SERIAL && $4 == /dev/loop* && -b $4 ]]
test "$(readlink -f "$4")" = "$(readlink -f /dev/oracleoci/oraclevdb)"
printf '%s\n' 0123456789abcdef0123456789abcdef
PROBE
sed -i "s|serial=\$(lsblk |serial=\$(/usr/local/lib/ts-orch/e2e-lsblk |" /usr/local/lib/ts-orch/data-mount-check.sh
