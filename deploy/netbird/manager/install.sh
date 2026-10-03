#!/usr/bin/env bash
# Install the NetBird manager on ts-ops: combined server + dashboard
# Quadlets, the nightly store backup, and ntfy failure hooks. The routing peer
# is separate (install-routing-peer.sh). Touches nothing Forgejo-owned;
# uninstall.sh reverses it.
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
STACK=/opt/ts-ops/netbird
CONFIG=/etc/netbird/config.yaml
DATA=/var/srv/appdata/netbird
LIBEXEC=/usr/local/libexec/homelab/netbird
HOOKED_UNITS=(netbird-firewall.service netbird-server.service netbird-dashboard.service netbird-backup.service)

usage() {
  cat <<'USAGE'
Usage: install.sh [--dry-run] [--help]

Run as root from /opt/ts-ops/netbird on ts-ops after the
OpenBao materializer has rendered /etc/netbird/config.yaml. Installs the
NetBird server and dashboard Quadlets (loopback publishes plus UDP 3478), the
store backup timer, and OnFailure ntfy hooks, then starts the server and
dashboard. Never restarts Forgejo, Postgres, or Caddy. Create the owner with
setup-owner.sh before Caddy publishes netbird.terrascale.tech.
USAGE
}
dry_run=0
while [[ $# -gt 0 ]]; do
  case "$1" in
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
  echo "install.sh: $*" >&2
  exit 1
}

[[ $EUID -eq 0 ]] || fail "run as root"
[[ "$(hostname -s)" == ts-ops ]] || fail "refusing to run outside ts-ops"
[[ "$root" == "$STACK" ]] || fail "run from the staged stack at $STACK"
[[ -f "$CONFIG" && "$(stat -c '%U:%G %a' "$CONFIG")" == 'root:root 600' ]] \
  || fail "$CONFIG must be materialized by OpenBao (target forgejo-oci-netbird) as root:root 0600"
grep -q '{{' "$CONFIG" && fail "$CONFIG still contains template placeholders"

# The ports must be free or already held by this stack.
# Any listener on the port counts, whatever address it binds.
for spec in tcp:18080 tcp:18081 udp:3478; do
  IFS=: read -r proto port <<<"$spec"
  holder=$(ss -Hlnp --"$proto" "sport = :$port" | grep -v -E 'netbird|conmon|podman|netavark|aardvark' || true)
  [[ -z "$holder" ]] || fail "$proto port $port is already in use: $holder"
done

if [[ "$dry_run" -eq 1 ]]; then
  echo "[dry-run] preflight passed; would install Quadlets, the STUN firewall rule, backup timer, ${#HOOKED_UNITS[@]} OnFailure hooks, then start netbird-server and netbird-dashboard"
  exit 0
fi

install -d -m 0700 "$DATA/data" "$DATA/backups"
install -m 0644 "$root/quadlets/netbird.network" "$root/quadlets/netbird-server.container" \
  "$root/quadlets/netbird-dashboard.container" /etc/containers/systemd/

install -d -m 0755 "$LIBEXEC"
install -m 0755 "$root/netbird-backup" "$root/netbird-firewall" "$LIBEXEC/"
install -m 0644 "$root/systemd/netbird-backup.service" "$root/systemd/netbird-backup.timer" \
  "$root/systemd/netbird-firewall.service" /etc/systemd/system/

if [[ -f /etc/systemd/system/ntfy-failure@.service ]]; then
  for unit in "${HOOKED_UNITS[@]}"; do
    install -d -m 0755 "/etc/systemd/system/${unit}.d"
    printf '[Unit]\nOnFailure=ntfy-failure@%%n.service\n' >"/etc/systemd/system/${unit}.d/onfailure-ntfy.conf"
  done
fi

systemctl daemon-reload
systemctl enable --now netbird-firewall.service
systemctl start netbird-server.service netbird-dashboard.service
systemctl enable --now netbird-backup.timer
echo "netbird manager installed; next: setup-owner.sh, then caddy validate + reload"
