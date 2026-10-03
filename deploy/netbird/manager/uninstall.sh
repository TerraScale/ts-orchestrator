#!/usr/bin/env bash
# Remove the NetBird operator gateway from ts-ops, returning the host
# to its Forgejo-only baseline. Caddy's netbird.terrascale.tech block is removed
# separately in the reviewed Caddyfile. Keeps the store unless --purge-data.
# Always forgets the routing peer's identity (/var/lib/netbird): delete the
# ts-ops peer in the manager too; a reinstall enrolls it with a new setup key.
set -euo pipefail

DATA=/var/srv/appdata/netbird
HOOKED_UNITS=(netbird-firewall.service netbird-peer-firewall.service netbird-server.service
  netbird-dashboard.service netbird.service netbird-backup.service)

purge=0
case "${1:-}" in
  "") ;;
  --purge-data) purge=1 ;;
  --help | -h)
    cat <<'USAGE'
Usage: uninstall.sh [--purge-data]

Removes the NetBird manager, dashboard and the ts-ops routing peer. The routing
peer's client state (/var/lib/netbird: WireGuard key and login) is always
deleted, so the peer must also be deleted in the manager and a reinstall needs
a new setup key. --purge-data also deletes the manager store and its backups.
USAGE
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
# The routing peer's client identity; the manager's store lives in $DATA.
rm -rf /var/lib/netbird
systemctl stop netbird-dashboard.service netbird-server.service netbird-network.service 2>/dev/null || true
rm -f /etc/containers/systemd/netbird.network /etc/containers/systemd/netbird-server.container \
  /etc/containers/systemd/netbird-dashboard.container
systemctl disable --now netbird-firewall.service netbird-peer-firewall.service 2>/dev/null || true
rm -f /etc/systemd/system/netbird-backup.service /etc/systemd/system/netbird-backup.timer \
  /etc/systemd/system/netbird-firewall.service /etc/systemd/system/netbird-peer-firewall.service
for unit in "${HOOKED_UNITS[@]}"; do
  rm -f "/etc/systemd/system/${unit}.d/onfailure-ntfy.conf"
  [[ ! -d "/etc/systemd/system/${unit}.d" ]] || rmdir --ignore-fail-on-non-empty "/etc/systemd/system/${unit}.d"
done
rm -rf /etc/systemd/system/netbird.service.d /usr/local/libexec/homelab/netbird
rm -f /etc/apt/sources.list.d/netbird.list /usr/share/keyrings/netbird-archive-keyring.gpg
# IPv4 forwarding returns to the distribution default at the next boot.
rm -f /etc/sysctl.d/99-netbird-routing.conf
systemctl daemon-reload
podman network rm netbird 2>/dev/null || true
# Server configuration (config.yaml, rendered by OpenBao) only; the client
# state was removed above.
rm -rf /etc/netbird
if [[ "$purge" -eq 1 ]]; then
  rm -rf "$DATA"
fi
echo "netbird removed; remove the Caddy site block and reload Caddy to finish"
