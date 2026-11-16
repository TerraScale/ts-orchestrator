#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 && $# == 1 ]] || { echo "Usage: sudo bash $0 <snapshot-directory>" >&2; exit 2; }
snapshot=$(realpath "$1")
tar -tzf "$snapshot/files.tgz" > /dev/null
units=(ts-prometheus.service ts-alertmanager.service ts-alert-delivery.service ts-alert-delivery-token.path ts-alert-delivery-token.service)
for unit in "${units[@]}"; do
  [[ -f $snapshot/$unit.state ]]
done
for unit in "${units[@]}"; do
  if [[ -e /etc/systemd/system/$unit || -L /etc/systemd/system/$unit ]]; then
    systemctl disable --now "$unit"
    rm -f "/etc/systemd/system/$unit"
  fi
done
rm -rf /etc/ts-monitoring /usr/local/lib/ts-monitoring
tar -C / -xzf "$snapshot/files.tgz"
systemctl daemon-reload
for unit in "${units[@]}"; do
  if grep -Fxq UnitFileState=enabled "$snapshot/$unit.state"; then
    systemctl enable "$unit"
  elif grep -Fxq UnitFileState=enabled-runtime "$snapshot/$unit.state"; then
    systemctl enable --runtime "$unit"
  fi
  if grep -Fxq ActiveState=active "$snapshot/$unit.state"; then
    systemctl start "$unit"
  fi
done
printf 'monitoring: restored files and unit states from %s; TSDB, silences and delivery state retained\n' "$snapshot"
