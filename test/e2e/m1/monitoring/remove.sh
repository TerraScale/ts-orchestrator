#!/usr/bin/env bash
set -euo pipefail
installer=$1
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mount --make-rprivate /
for tree in etc local var; do
  mkdir -p "$work/$tree-upper" "$work/$tree-work"
done
mount -t overlay -o "lowerdir=/etc,upperdir=$work/etc-upper,workdir=$work/etc-work" overlay /etc
mount -t overlay -o "lowerdir=/usr/local,upperdir=$work/local-upper,workdir=$work/local-work" overlay /usr/local
mount -t overlay -o "lowerdir=/var/lib,upperdir=$work/var-upper,workdir=$work/var-work" overlay /var/lib
for directory in /etc/systemd /etc/systemd/system; do
  if [[ -L $directory ]]; then
    rm "$directory"
    mkdir "$directory"
  fi
done
mkdir -p "$work/bin" /etc/ts-monitoring/production /etc/systemd/system /usr/local/lib/ts-monitoring /var/lib/ts-alerts
export MONITORING_REMOVAL_LOG="$work/systemctl"
export MONITORING_HOSTS_LOG="$work/hosts"
cat > "$work/bin/systemctl" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$MONITORING_REMOVAL_LOG"
SH
cat > "$work/bin/ssh" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$1" >> "$MONITORING_HOSTS_LOG"
bash -s -- --remove --local
SH
chmod +x "$work/bin/"*
export PATH="$work/bin:$PATH"
printf 'retained\n' > /var/lib/ts-alerts/email-ledger.json
for unit in ts-prometheus ts-alertmanager ts-alert-delivery; do
  printf 'journey\n' > "/etc/systemd/system/$unit.service"
done
printf 'journey\n' > /usr/local/lib/ts-monitoring/prometheus
bash "$installer" --remove --local
for unit in ts-prometheus ts-alertmanager ts-alert-delivery; do
  [[ ! -e /etc/systemd/system/$unit.service ]]
  grep -Fxq "disable --now $unit.service" "$MONITORING_REMOVAL_LOG"
done
[[ ! -e /etc/ts-monitoring/production && ! -e /usr/local/lib/ts-monitoring ]]
grep -Fxq retained /var/lib/ts-alerts/email-ledger.json
bash -s -- --remove --local < "$installer"
bash "$installer" --remove --fleet
[[ $(wc -l < "$MONITORING_HOSTS_LOG") == 3 ]]
for host in ts-sjc-1 ts-fra-1 ts-gru-1; do
  grep -Fxq "$host" "$MONITORING_HOSTS_LOG"
done
printf 'monitoring: real installer removes local/fleet units and assets, supports SSH stdin, preserves the ledger and is idempotent\n'
