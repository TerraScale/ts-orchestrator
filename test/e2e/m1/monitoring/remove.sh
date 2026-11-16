#!/usr/bin/env bash
set -euo pipefail
installer=$1
previous=$2
agent=$3
real_curl=$(command -v curl)
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
hostname ts-gru-1
sed -i 's/^hosts:.*/hosts: files dns/' /etc/nsswitch.conf
sed -i '$a 10.0.0.1 ts-gru-1.nb.ts.internal' /etc/hosts
mkdir -p "$work/bin" /etc/ts-monitoring/production /etc/systemd/system /usr/local/lib/ts-monitoring /var/lib/ts-alerts
export MONITORING_REMOVAL_LOG="$work/systemctl"
export MONITORING_HOSTS_LOG="$work/hosts"
export MONITORING_SHIPPED="$work/shipped.tgz"
cat > "$work/bin/systemctl" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$MONITORING_REMOVAL_LOG"
SH
cat > "$work/bin/ssh" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$1" >> "$MONITORING_HOSTS_LOG"
tee "$MONITORING_SHIPPED" | bash -c "$2"
SH
cat > "$work/bin/sudo" <<'SH'
#!/usr/bin/env bash
exec "$@"
SH
cat > "$work/bin/curl" <<SH
#!/usr/bin/env bash
for argument; do [[ \$argument == http*://* ]] && url=\$argument; done
case \$url in
  https://*) exec $real_curl "\$@" ;;
  */services) printf '[]\\n' ;;
  */orchestrator/metrics) printf 'ts_orch_mesh_store_observed 1\\n' ;;
  */metrics) printf 'ts_host_service_tasks_expected{service="%s"} 1\\n' terrabase ts-auth ts-dashboard ;;
  http://127.0.0.1:909[034]/*) printf 'ok\\n' ;;
  *) exit 7 ;;
esac
SH
chmod +x "$work/bin/"*
export PATH="$work/bin:$PATH"
printf 'retained\n' > /var/lib/ts-alerts/email-ledger.json
for unit in ts-prometheus.service ts-alertmanager.service ts-alert-delivery.service ts-alert-delivery-token.path ts-alert-delivery-token.service; do
  printf 'journey\n' > "/etc/systemd/system/$unit"
done
printf 'journey\n' > /usr/local/lib/ts-monitoring/prometheus
bash "$installer" --remove --local
for unit in ts-prometheus.service ts-alertmanager.service ts-alert-delivery.service ts-alert-delivery-token.path ts-alert-delivery-token.service; do
  [[ ! -e /etc/systemd/system/$unit ]]
  grep -Fxq "disable --now $unit" "$MONITORING_REMOVAL_LOG"
done
[[ ! -e /etc/ts-monitoring/production && ! -e /usr/local/lib/ts-monitoring ]]
grep -Fxq retained /var/lib/ts-alerts/email-ledger.json
bash -s -- --remove --local < "$installer"
bash "$installer" --remove --fleet
[[ $(wc -l < "$MONITORING_HOSTS_LOG") == 3 ]]
for host in ts-sjc-1 ts-fra-1 ts-gru-1; do
  grep -Fxq "$host" "$MONITORING_HOSTS_LOG"
done
install -D -m 0755 "$agent" /usr/local/bin/ts-orch
: > "$MONITORING_REMOVAL_LOG"
bash "$previous" ts-gru-1 > "$work/previous.log" 2>&1 || { tail -20 "$work/previous.log"; exit 1; }
[[ $(tail -n 1 "$MONITORING_HOSTS_LOG") == ts-gru-1 ]]
mkdir "$work/shipped"
tar -xzf "$MONITORING_SHIPPED" -C "$work/shipped"
for unit in ts-prometheus.service ts-alertmanager.service ts-alert-delivery.service ts-alert-delivery-token.path ts-alert-delivery-token.service; do
  cmp "$work/shipped/production/$unit" "/etc/systemd/system/$unit"
done
[[ ! -e /etc/ts-monitoring/production/alertmanager.env ]]
grep -Eq "^enable ts-prometheus\.service ts-alertmanager\.service ts-alert-delivery\.service( |$)" "$MONITORING_REMOVAL_LOG"
cmp "$(dirname "$previous")/alertmanager.yml" /etc/ts-monitoring/production/alertmanager.yml
/usr/local/lib/ts-monitoring/prometheus --version > /dev/null
grep -Fxq retained /var/lib/ts-alerts/email-ledger.json
printf 'monitoring: real installer removes local/fleet units and assets, supports SSH stdin, preserves the ledger and is idempotent; the previous revision installs over the kept state\n'
