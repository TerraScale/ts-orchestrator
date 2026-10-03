#!/usr/bin/env bash
# Remove the NetBird operator gateway from ts-ops, returning the host
# to its Forgejo-only baseline. Caddy's netbird.terrascale.tech block is removed
# separately in the reviewed Caddyfile. Keeps the store unless --purge-data.
set -euo pipefail

DATA=/var/srv/appdata/netbird
HOOKED_UNITS=(netbird-firewall.service netbird-peer-firewall.service netbird-server.service
  netbird-dashboard.service netbird.service netbird-backup.service)

purge=0
case "${1:-}" in
  "") ;;
  --purge-data) purge=1 ;;
  --help | -h)
    echo "Usage: uninstall.sh [--purge-data]"
    exit 0
    ;;
  *)
    echo "unknown argument: $1" >&2
    exit 2
    ;;
esac

[[ $EUID -eq 0 ]] || {
  echo "run as root" >&2
  exit 1
}
[[ "$(hostname -s)" == ts-ops ]] || {
  echo "refusing to run outside ts-ops" >&2
  exit 1
}

systemctl disable --now netbird-backup.timer 2>/dev/null || true
if command -v netbird >/dev/null; then
  netbird down 2>/dev/null || true
  netbird service stop 2>/dev/null || true
  netbird service uninstall 2>/dev/null || true
  apt-mark unhold netbird >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get purge -y netbird
fi
systemctl stop netbird-dashboard.service netbird-server.service netbird-network.service 2>/dev/null || true
rm -f /etc/containers/systemd/netbird.network /etc/containers/systemd/netbird-server.container \
  /etc/containers/systemd/netbird-dashboard.container
systemctl disable --now netbird-firewall.service netbird-peer-firewall.service 2>/dev/null || true
rm -f /etc/systemd/system/netbird-backup.service /etc/systemd/system/netbird-backup.timer \
  /etc/systemd/system/netbird-firewall.service /etc/systemd/system/netbird-peer-firewall.service
for unit in "${HOOKED_UNITS[@]}"; do
  rm -f "/etc/systemd/system/${unit}.d/onfailure-ntfy.conf"
done
rm -rf /etc/systemd/system/netbird.service.d /usr/local/libexec/homelab/netbird
rm -f /etc/apt/sources.list.d/netbird.list /usr/share/keyrings/netbird-archive-keyring.gpg
# IPv4 forwarding returns to the distribution default at the next boot.
rm -f /etc/sysctl.d/99-netbird-routing.conf
systemctl daemon-reload
podman network rm netbird 2>/dev/null || true
rm -rf /etc/netbird
if [[ "$purge" -eq 1 ]]; then
  rm -rf "$DATA"
fi
echo "netbird removed; remove the Caddy site block and reload Caddy to finish"
