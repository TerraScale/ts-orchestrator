#!/usr/bin/env bash
set -euo pipefail

home=/home/terrascale
install -d -m 0700 -o terrascale -g terrascale "$home/.ssh"
keys=$(curl -fsS -H 'Authorization: Bearer Oracle' http://169.254.169.254/opc/v2/instance/metadata/ssh_authorized_keys)
[[ -n $keys ]] || { echo "IMDSv2 returned no ssh_authorized_keys" >&2; exit 1; }
printf '%s\n' "$keys" > "$home/.ssh/authorized_keys"
chown terrascale:terrascale "$home/.ssh/authorized_keys"
chmod 0600 "$home/.ssh/authorized_keys"
