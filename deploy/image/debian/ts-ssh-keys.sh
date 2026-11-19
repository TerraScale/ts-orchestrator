#!/usr/bin/env bash
set -euo pipefail

home=/home/terrascale
umask 077
mkdir -p "$home/.ssh"
keys=$(mktemp "$home/.ssh/.authorized_keys.XXXXXX")
trap 'rm -f "$keys"' EXIT
curl -fsS --connect-timeout 2 --max-time 8 -H 'Authorization: Bearer Oracle' \
	http://169.254.169.254/opc/v2/instance/metadata/ssh_authorized_keys > "$keys"
[[ -s $keys ]] || { echo "IMDSv2 returned no ssh_authorized_keys" >&2; exit 1; }
mv -fT "$keys" "$home/.ssh/authorized_keys"
cat "$home/.ssh/authorized_keys"
