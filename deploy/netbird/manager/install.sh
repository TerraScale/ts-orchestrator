#!/usr/bin/env bash
# Install the NetBird manager on ts-ops: combined server + dashboard
# Quadlets, the nightly store backup, and ntfy failure hooks. The routing peer
# is separate (install-routing-peer.sh). Changes only NetBird-owned resources;
# uninstall.sh reverses it.
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
STACK=/opt/ts-ops/netbird
CONFIG=/run/terrascale-netbird/config.yaml
DATA=/var/srv/appdata/netbird
LIBEXEC=/usr/local/libexec/homelab/netbird
# gru-1's OCI Vault; ts-ops reads its NetBird secrets with its instance
# principal (docs/secrets.md).
VAULT=ocid1.vault.oc1.sa-saopaulo-1.ffvmfu2naagt6.abtxeljr7ebplea4ua3memgthsupcfn3crg6d56vipsw7o2butchdrx3urmq
HOOKED_UNITS=(netbird-firewall.service netbird-server.service netbird-dashboard.service netbird-backup.service)

usage() {
  cat <<'USAGE'
Usage: install.sh [--dry-run] [--help]

Run as root from /opt/ts-ops/netbird on ts-ops with ts-orch on PATH. Renders
/run/terrascale-netbird/config.yaml from OCI Vault with the instance principal, installs
the NetBird server and dashboard Quadlets (loopback publishes plus UDP 3478), the
store backup timer, and OnFailure ntfy hooks, then starts the server and
dashboard. Never restarts Caddy or unrelated host services. Create the owner with
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
[[ -x /usr/local/bin/ts-orch ]] || fail "/usr/local/bin/ts-orch must be installed for the Vault render and server restart hook"

# The ports must be free or already held by this stack. Any non-runtime
# listener on the port fails, whatever address it binds. Rootful Podman
# publishes through netavark DNAT with no listening socket, so the publishing
# containers are checked separately and unconditionally: only netbird-server
# and netbird-dashboard may publish these ports.
published=$(podman ps --format '{{.Names}} {{.Ports}}')
for spec in tcp:18080 tcp:18081 udp:3478; do
  IFS=: read -r proto port <<<"$spec"
  listeners=$(ss -Hlnp --"$proto" "sport = :$port" || true)
  holder=$(grep -v -E 'netbird|conmon|podman|netavark|aardvark|rootlessport' <<<"$listeners" || true)
  [[ -z "$holder" ]] || fail "$proto port $port is already in use: $holder"
  others=$(grep -E "[:]$port->[0-9]+/$proto" <<<"$published" | awk '{ print $1 }' \
    | grep -v -x -E 'netbird-server|netbird-dashboard' || true)
  [[ -z "$others" ]] || fail "$proto port $port is published by another container: $others"
done

if [[ "$dry_run" -eq 1 ]]; then
  echo "[dry-run] preflight passed; would render $CONFIG from OCI Vault, install Quadlets, the STUN firewall rule, backup timer, ${#HOOKED_UNITS[@]} OnFailure hooks, then start netbird-server and netbird-dashboard"
  exit 0
fi

install -d -m 0700 "$(dirname "$CONFIG")"
/usr/local/bin/ts-orch vault render --vault-id "$VAULT" --scope gru-1 --template "$root/templates/config.yaml.tmpl" --out "$CONFIG"
[[ "$(stat -c '%U:%G %a' "$CONFIG")" == 'root:root 600' ]] || fail "$CONFIG must be root:root 0600"

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
# Create the bridge first: netbird-firewall's STUN rule hardcodes its subnet,
# so drift fails before any service is up. Quadlet generates
# netbird-network.service from netbird.network.
systemctl start netbird-network.service
bridge=$(podman network inspect netbird --format '{{ (index .Subnets 0).Subnet }}')
[[ "$bridge" == 10.89.77.0/24 ]] || fail "netbird bridge subnet $bridge does not match netbird-firewall's 10.89.77.0/24"
# No `enable`: these are Quadlet-generated units. systemctl enable refuses
# them ("Unit ... is transient or generated"); the Quadlet generator links them
# into multi-user.target.wants from their [Install] WantedBy= (on ts-ops:
# is-enabled=generated, /run/systemd/generator/multi-user.target.wants).
systemctl start netbird-server.service netbird-dashboard.service
systemctl enable --now netbird-backup.timer
echo "netbird manager installed; next: setup-owner.sh, then caddy validate + reload"
