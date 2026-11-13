#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
trap 'sudo rm -rf "$work"; report' EXIT

begin "revision admission, retained Vault policy and installer metadata boundary"
bash "$here/revision-gate/run.sh" "$bin"
bash "$here/vault-policy/run.sh" "$bin"
bash "$here/installer-metadata/run.sh" "$bin"
end "revision refusals, safe policy narrowing and persistent metadata rules"

begin "release preflight platform identity"
mkdir -p "$work/preflight-sys/class/dmi/id"
printf 'OracleCloud.com\n' > "$work/preflight-sys/class/dmi/id/chassis_asset_tag"
sudo unshare --mount --net bash -s -- "$bin" "$work" <<'SH_PREFLIGHT'
set -euo pipefail
bin=$1
work=$2
mount --make-rprivate /
mount --bind "$work/preflight-sys" /sys
if "$bin" release preflight > "$work/preflight-output" 2>&1; then
	cat "$work/preflight-output"
	exit 1
fi
grep "Vault secrets need OCI instance metadata" "$work/preflight-output"
echo "Oracle release preflight refuses unavailable instance identity"
printf 'Local\n' > "$work/preflight-sys/class/dmi/id/chassis_asset_tag"
"$bin" release preflight
echo "Local release preflight needs no OCI credentials"
SH_PREFLIGHT
end "Oracle identity is required; local hosts need no OCI credentials"
