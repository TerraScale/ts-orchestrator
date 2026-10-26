#!/usr/bin/env bash
set -euo pipefail
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

# Only the explicit host invocation deploys; --check downloads and validates locally.
if [[ $# == 1 && $1 != --local && $1 != --check ]]; then
  [[ $1 != -* && $1 =~ ^[a-zA-Z0-9_.@-]+$ ]] || { echo 'Invalid SSH host' >&2; exit 2; }
  tar -C "$source_dir/.." -czf - production slo-rules.yml | ssh "$1" '
    set -eu
    staging=$(mktemp -d)
    trap '\''rm -rf -- "$staging"'\'' EXIT HUP INT TERM
    tar -xzf - -C "$staging"
    sudo bash "$staging/production/install.sh" --local
  '
  exit
fi
[[ $# == 1 && ( $1 == --local || $1 == --check ) ]] || {
  echo "Usage: $0 <SSH-host> | --check" >&2; exit 2;
}
mode=$1
if [[ $mode == --local && $EUID != 0 ]]; then
  echo 'Remote installation requires sudo/root' >&2; exit 2
fi
# Global help dispatches before runtime startup; never probe the bare daemon command.
if [[ $mode == --local ]]; then
  if ! help_output=$(timeout --kill-after=1s 5s /usr/local/bin/ts-orch --help 2>&1) ||
    ! grep -Eq '^  alert-delivery[[:space:]]' <<<"$help_output"; then
    echo 'Install a ts-orch release supporting alert-delivery before installing monitoring' >&2
    exit 2
  fi
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
"$prom_dir/promtool" check config "$source_dir/prometheus.yml"
(cd "$source_dir" && "$prom_dir/promtool" test rules operational-rules.test.yml host-storage-rules.test.yml)
"$alert_dir/amtool" check-config "$source_dir/alertmanager.yml"
if [[ $mode == --check ]]; then exit; fi

# Config and release checks above must pass before any installed state changes.
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
put "$source_dir/../slo-rules.yml" /etc/ts-monitoring/slo-rules.yml 0644
for config in prometheus.yml alertmanager.yml operational-rules.yml host-storage-rules.yml; do
  put "$source_dir/$config" "/etc/ts-monitoring/production/$config" 0644
done
for unit in ts-prometheus.service ts-alertmanager.service ts-alert-delivery.service; do
  put "$source_dir/$unit" "/etc/systemd/system/$unit" 0644
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
