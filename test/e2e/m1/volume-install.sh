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
sed -i "s|serial=\$(lsblk |serial=\$($work/probe-bin/lsblk |" /usr/local/lib/ts-orch/data-mount-check.sh
