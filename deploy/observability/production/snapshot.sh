#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Snapshot requires sudo/root' >&2; exit 2; }
umask 077
mkdir -p /var/backups/ts-monitoring
snapshot=$(mktemp -d /var/backups/ts-monitoring/before-XXXXXXXX)
paths=()
for path in etc/ts-monitoring usr/local/lib/ts-monitoring; do
  if [[ -e /$path ]]; then paths+=("$path"); fi
done
for unit in ts-prometheus.service ts-alertmanager.service ts-alert-delivery.service ts-alert-delivery-token.path ts-alert-delivery-token.service; do
  systemctl show --property=LoadState,ActiveState,UnitFileState "$unit" > "$snapshot/$unit.state"
  path=etc/systemd/system/$unit
  if [[ -e /$path || -L /$path ]]; then paths+=("$path"); fi
done
tar -C / -czf "$snapshot/files.tgz" --files-from /dev/null "${paths[@]}"
printf '%s\n' "$snapshot"
