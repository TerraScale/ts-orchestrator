#!/usr/bin/env bash
# Install and enroll ts-ops as the NetBird routing peer for the GRU
# cell: the pinned and held netbird client, IPv4 forwarding, the WireGuard
# firewall rule, client limits, and ntfy failure hooks. Requires the manager
# (install.sh). The peer reaches its manager through the public name: OCI
# hairpins this VM's own public IP.
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
CLIENT_VERSION=0.79.0
APT_KEY_FINGERPRINT=EFE37DF047DF7CCDF1FC54FA83F79AD029778355
APT_KEYRING=/usr/share/keyrings/netbird-archive-keyring.gpg
APT_SOURCE=/etc/apt/sources.list.d/netbird.list
LIBEXEC=/usr/local/libexec/homelab/netbird

usage() {
  cat <<'USAGE'
Usage: install-routing-peer.sh --setup-key-file PATH [--dry-run]

Registers this host with https://netbird.terrascale.tech as routing peer
ts-ops. It installs and holds netbird=0.79.0 from the fingerprint-
verified NetBird apt repository, enables IPv4 forwarding, and opens UDP 51820
through the host firewall (netbird-peer-firewall.service). DNS management and
client routes stay off, the NetBird SSH server stays disabled, and the public
address is pinned so peers connect directly. The one-off setup key file must
be root-owned mode 0600; delete it afterwards.
USAGE
}

key_file=""
dry_run=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --setup-key-file)
      key_file=${2:-}
      shift
      ;;
    --dry-run) dry_run=1 ;;
    --help | -h)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

fail() {
  echo "install-routing-peer.sh: $*" >&2
  exit 1
}

[[ $EUID -eq 0 ]] || fail "run as root"
[[ "$(hostname -s)" == ts-ops ]] || fail "refusing to run outside ts-ops"
[[ -n "$key_file" && -f "$key_file" && ! -L "$key_file" && "$(stat -c '%U %a' "$key_file")" == 'root 600' ]] \
  || fail "--setup-key-file must name a root-owned 0600 file"
systemctl is-active --quiet netbird-server.service || fail "install the NetBird manager (install.sh) first"
if ! ip link show wt0 >/dev/null 2>&1; then
  holder=$(ss -Hlnu "sport = :51820" || true)
  [[ -z "$holder" ]] || fail "udp 51820 is already in use: $holder"
fi

if [[ "$dry_run" -eq 1 ]]; then
  echo "[dry-run] preflight passed; would install and hold netbird=$CLIENT_VERSION, enable IPv4 forwarding and the peer firewall, apply client limits, and enroll ts-ops with the protected setup-key file"
  exit 0
fi

if ! apt-mark showhold | grep -qx netbird || [[ "$(dpkg-query -W -f '${Version}' netbird 2>/dev/null)" != "$CLIENT_VERSION" ]]; then
  key=$(mktemp)
  trap 'rm -f "$key"' EXIT
  curl -fsSL https://pkgs.netbird.io/debian/public.key -o "$key"
  fingerprint=$(gpg --show-keys --with-colons "$key" | awk -F: '$1 == "fpr" { print $10; exit }')
  [[ "$fingerprint" == "$APT_KEY_FINGERPRINT" ]] || fail "NetBird apt key fingerprint $fingerprint is not $APT_KEY_FINGERPRINT"
  gpg --dearmor --yes -o "$APT_KEYRING" "$key"
  echo "deb [signed-by=$APT_KEYRING] https://pkgs.netbird.io/debian stable main" >"$APT_SOURCE"
  apt-get update -o Dir::Etc::sourcelist="$APT_SOURCE" -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0
  apt-mark unhold netbird >/dev/null 2>&1 || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "netbird=$CLIENT_VERSION"
  apt-mark hold netbird
fi
netbird service install >/dev/null 2>&1 || true

install -m 0755 "$root/netbird-firewall" "$LIBEXEC/"
install -m 0644 "$root/systemd/netbird-peer-firewall.service" /etc/systemd/system/
install -d -m 0755 /etc/systemd/system/netbird.service.d
install -m 0644 "$root/systemd/netbird-client-limits.conf" /etc/systemd/system/netbird.service.d/limits.conf
install -m 0644 "$root/systemd/netbird-client-firewall.conf" /etc/systemd/system/netbird.service.d/firewall.conf
if [[ -f /etc/systemd/system/ntfy-failure@.service ]]; then
  printf '[Unit]\nOnFailure=ntfy-failure@%%n.service\n' >/etc/systemd/system/netbird.service.d/onfailure-ntfy.conf
  install -d -m 0755 /etc/systemd/system/netbird-peer-firewall.service.d
  printf '[Unit]\nOnFailure=ntfy-failure@%%n.service\n' \
    >/etc/systemd/system/netbird-peer-firewall.service.d/onfailure-ntfy.conf
fi
install -m 0644 "$root/systemd/99-netbird-routing.conf" /etc/sysctl.d/99-netbird-routing.conf
sysctl -q -p /etc/sysctl.d/99-netbird-routing.conf

systemctl daemon-reload
systemctl enable --now netbird-peer-firewall.service
# Re-runs keep an enrolled routing peer connected; resource limits apply live.
if systemctl is-active --quiet netbird.service; then
  systemctl set-property --runtime netbird.service CPUWeight=50 MemoryHigh=128M MemoryMax=192M
else
  systemctl enable --now netbird.service
fi

netbird up \
  --management-url https://netbird.terrascale.tech \
  --setup-key-file "$key_file" \
  --hostname ts-ops \
  --disable-dns \
  --disable-client-routes \
  --allow-server-ssh=false \
  --external-ip-map 163.176.73.79/10.250.10.155
netbird status
