#!/usr/bin/env bash
set -euo pipefail
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd)

if [[ ${1:-} == --remove ]]; then
  shift
  if [[ $# == 1 && $1 == --fleet ]]; then
    while read -r host; do
      bash "$source_dir/install.sh" --remove "$host"
    done < <(awk -F- '!seen[$2]++' "$source_dir/hosts.txt")
  elif [[ $# == 1 && $1 == --local ]]; then
    [[ $EUID == 0 ]] || { echo 'Removal requires sudo/root' >&2; exit 2; }
    for unit in ts-prometheus.service ts-alertmanager.service ts-alert-delivery.service; do
      if [[ -f /etc/systemd/system/$unit ]]; then
        systemctl disable --now "$unit"
        rm -f "/etc/systemd/system/$unit"
      fi
    done
    rm -rf /etc/ts-monitoring/production /usr/local/lib/ts-monitoring
    systemctl daemon-reload
  elif [[ $# == 1 && $1 != -* && $1 =~ ^[a-zA-Z0-9_.@-]+$ ]]; then
    ssh "$1" 'sudo bash -s -- --remove --local' < "$source_dir/install.sh"
  else
    echo "Usage: $0 --remove <SSH-host> | --remove --fleet" >&2; exit 2
  fi
  exit
fi
if [[ $# == 1 && $1 == --fleet ]]; then
  while read -r host; do
    bash "$source_dir/install.sh" "$host"
  done < <(awk -F- '!seen[$2]++' "$source_dir/hosts.txt")
  exit
fi
if [[ $# == 1 && $1 != --local && $1 != --check ]]; then
  [[ $1 != -* && $1 =~ ^[a-zA-Z0-9_.@-]+$ ]] || { echo 'Invalid SSH host' >&2; exit 2; }
  rendered=$(mktemp -d)
  trap 'rm -rf -- "$rendered"' EXIT
  go -C "$source_dir/../../../scripts/monitoring" run . "$rendered/rendered" "$source_dir/../../.."
  cp -a "$source_dir" "$rendered/production"
  tar -C "$rendered" -czf - production rendered | ssh "$1" '
    set -eu
    staging=$(mktemp -d)
    trap '\''rm -rf -- "$staging"'\'' EXIT HUP INT TERM
    tar -xzf - -C "$staging"
    sudo bash "$staging/production/install.sh" --local
  '
  exit
fi
[[ ( $# == 1 && $1 == --local ) || ( $# -ge 1 && $# -le 2 && $1 == --check ) ]] || {
  echo "Usage: $0 <SSH-host> | --fleet | --check" >&2; exit 2;
}
mode=$1
check_tools=${2:-}
rendered="$source_dir/../rendered"
if [[ $mode == --local ]]; then
  config_dir="$rendered/$(hostname -s)"
  [[ -f $config_dir/prometheus.yml ]] || { echo "Host is not an inventory monitoring backend" >&2; exit 2; }
monitor_address=$(python3 -c 'import ipaddress,socket,sys; address=socket.gethostbyname(sys.argv[1]+".nb.ts.internal"); assert ipaddress.ip_address(address).is_private; print(address)' "$(hostname -s)")
printf 'MONITOR_ADDRESS=%s\n' "$monitor_address" > "$config_dir/alertmanager.env"
fi
if [[ $mode == --local && $EUID != 0 ]]; then
  echo 'Remote installation requires sudo/root' >&2; exit 2
fi
if [[ $mode == --local ]]; then
  if ! help_output=$(timeout --kill-after=1s 5s /usr/local/bin/ts-orch --help 2>&1) ||
    ! grep -Eq '^  alert-delivery[[:space:]]' <<<"$help_output"; then
    echo 'Install a ts-orch release supporting alert-delivery before installing monitoring' >&2
    exit 2
  fi
  while read -r discovery; do
    if ! curl --fail --silent --show-error --max-time 5 "$discovery" --output /dev/null; then
      echo 'Upgrade every host agent before installing task discovery; no monitoring changes made' >&2
      exit 2
    fi
  done < <(python3 -c 'import json,sys; print("\n".join(d["url"] for j in json.load(open(sys.argv[1]))["scrape_configs"] for d in j.get("http_sd_configs", [])))' "$config_dir/prometheus.yml")
  checked=0
  while read -r discovery; do
    if ! metrics=$(curl --fail --silent --show-error --max-time 5 "${discovery%/services}/metrics"); then
      echo "Host task inventory unavailable: $discovery; no monitoring changes made" >&2
      exit 2
    fi
    for service in terrabase ts-auth ts-dashboard; do
      if ! grep -Eq "^ts_host_service_tasks_expected\{service=\"$service\"\} [0-9]+$" <<<"$metrics"; then
        echo "Upgrade host task inventory: $discovery ($service); no monitoring changes made" >&2
        exit 2
      fi
    done
    if ! curl --fail --silent --show-error --max-time 5 "${discovery%/services}/orchestrator/metrics" --output /dev/null; then
      echo "Upgrade host monitoring proxy: $discovery; no monitoring changes made" >&2
      exit 2
    fi
    checked=$((checked + 1))
  done < <(python3 -c 'import json,sys; print("\n".join(d["url"] for j in json.load(open(sys.argv[1]))["scrape_configs"] for d in j.get("http_sd_configs", [])))' "$config_dir/prometheus.yml")
  [[ $checked == $(wc -l < "$source_dir/hosts.txt") ]] || { echo 'Expected every configured host inventory endpoint' >&2; exit 2; }
  status=0
  relay_help=$(timeout --kill-after=1s 5s /usr/local/bin/ts-orch alert-delivery --help 2>&1) || status=$?
  if [[ $status != 1 || $relay_help != 'usage: ts-orch alert-delivery' ]]; then
    echo 'Installed ts-orch alert-delivery usage probe failed; no monitoring changes made' >&2
    exit 2
  fi
fi
case $(uname -m) in
  x86_64) arch=amd64
    prom_sha=2a542df32eac02ee17b9d844fb2aa1de00dafa5476579ba8a3ba862e9d572ea0
    alert_sha=265b9d1e55ef0d5306a436018af6d2b686c2ce051f03d968f7464ecb1372a7e8 ;;
  aarch64) arch=arm64
    prom_sha=f1f90ec08e849d494ca66c611470afc50192f0355f1a61c33f2cbde02d067823
    alert_sha=d98d6cbaf52151c7e76e24355fec88b11cebcb9875d4cdd8b76ddce7a7e5535c ;;
  *) echo 'Unsupported architecture' >&2; exit 2 ;;
esac
staging=$(mktemp -d)
trap 'rm -rf -- "$staging"' EXIT HUP INT TERM
if [[ $mode == --check ]]; then
  rendered="$staging/rendered"
  go -C "$source_dir/../../../scripts/monitoring" build -o "$staging/render-monitoring" .
  "$staging/render-monitoring" "$rendered" "$source_dir/../../.."
fi
for component in prometheus alertmanager; do
  if [[ $component == prometheus ]]; then version=3.15.0; checksum=$prom_sha
  else version=0.34.1; checksum=$alert_sha; fi
  archive="$component-$version.linux-$arch.tar.gz"
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    "https://github.com/prometheus/$component/releases/download/v$version/$archive" -o "$staging/$archive"
  (cd "$staging" && printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check --strict)
  tar -xzf "$staging/$archive" -C "$staging"
done
prom_dir="$staging/prometheus-3.15.0.linux-$arch"
alert_dir="$staging/alertmanager-0.34.1.linux-$arch"
for config in "$rendered"/*/prometheus.yml; do
  "$prom_dir/promtool" check config "$config"
done
if [[ $mode == --check ]]; then
  (cd "$source_dir/../../../test/e2e/m1/monitoring" && "$prom_dir/promtool" test rules rules.yml)
  python3 "$source_dir/../../../test/e2e/m1/monitoring/regions.py" "$rendered" "$prom_dir/promtool" "$staging/render-monitoring"
fi
"$alert_dir/amtool" check-config "$source_dir/alertmanager.yml"
if [[ $mode == --check ]]; then
  if [[ -n $check_tools ]]; then
    mkdir -p "$check_tools"
    cp "$prom_dir/prometheus" "$alert_dir/alertmanager" "$check_tools/"
    cp -a "$rendered" "$check_tools/"
  fi
  exit
fi

for account in ts-prometheus ts-alertmanager ts-alerts; do
  if ! id "$account" >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$account"
  fi
done
install -d -m 0755 /usr/local/lib/ts-monitoring /etc/ts-monitoring/production
changed=0
put() {
  if ! cmp -s "$1" "$2"; then
    install -m "$3" "$1" "$2"
    changed=1
  fi
}
put "$prom_dir/prometheus" /usr/local/lib/ts-monitoring/prometheus 0755
put "$prom_dir/promtool" /usr/local/lib/ts-monitoring/promtool 0755
put "$alert_dir/alertmanager" /usr/local/lib/ts-monitoring/alertmanager 0755
put "$alert_dir/amtool" /usr/local/lib/ts-monitoring/amtool 0755
for config in prometheus.yml rules.yml email-budget.json alertmanager.env; do
  put "$config_dir/$config" "/etc/ts-monitoring/production/$config" 0644
done
put "$source_dir/alertmanager.yml" /etc/ts-monitoring/production/alertmanager.yml 0644
for unit in ts-prometheus.service ts-alertmanager.service ts-alert-delivery.service; do
  unit_source="$source_dir/$unit"
  if [[ $unit == ts-alertmanager.service ]]; then unit_source="$config_dir/$unit"; fi
  put "$unit_source" "/etc/systemd/system/$unit" 0644
done
systemctl daemon-reload
systemctl enable ts-prometheus.service ts-alertmanager.service ts-alert-delivery.service
if [[ $changed == 1 ]]; then
  systemctl restart ts-alert-delivery.service ts-alertmanager.service ts-prometheus.service
else
  systemctl start ts-alert-delivery.service ts-alertmanager.service ts-prometheus.service
fi
curl --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 http://127.0.0.1:9090/-/ready
curl --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 http://127.0.0.1:9093/-/ready
curl --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 http://127.0.0.1:9094/healthz
