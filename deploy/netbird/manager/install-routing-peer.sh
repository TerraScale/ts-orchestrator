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
# ts-ops' public IP and its private VCN address; peers connect directly to the
# public one.
PUBLIC_IP=163.176.73.79
PRIVATE_IP=10.250.10.155

usage() {
  cat <<'USAGE'
Usage: install-routing-peer.sh [--setup-key-file PATH] [--dry-run]

Registers this host with https://netbird.terrascale.tech as routing peer
ts-ops. It installs and holds netbird=0.79.0 from the fingerprint-
verified NetBird apt repository, enables IPv4 forwarding, and opens UDP 51820
through the host firewall (netbird-peer-firewall.service). DNS management and
client routes stay off, the NetBird SSH server stays disabled, and the public
address is pinned so peers connect directly. First enrollment needs
--setup-key-file naming the one-off setup key, root-owned mode 0600; delete it
afterwards. Re-runs on an enrolled peer (client state in /var/lib/netbird and
`netbird status` logged in) omit the key and keep the peer's identity. With
saved client state the peer always logs in without the key first and uses a
given key only if NetBird then reports NeedsLogin or SessionExpired.
USAGE
}

key_file=""
dry_run=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --setup-key-file)
      [[ $# -ge 2 ]] || {
        echo "install-routing-peer.sh: --setup-key-file needs a path" >&2
        usage >&2
        exit 2
      }
      key_file=$2
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
# Saved client state: the peer's WireGuard identity in /var/lib/netbird.
has_client_state() { compgen -G '/var/lib/netbird/*.json' >/dev/null; }
peer_status() { netbird status 2>/dev/null || true; }
# Like internal/netbird/enroll.go, only an explicit authentication state
# warrants a setup key; LoginFailed is also reported for network errors.
needs_login() {
  local status
  status=$(peer_status)
  [[ "$status" == *NeedsLogin* || "$status" == *SessionExpired* ]]
}
# An enrolled peer keeps its identity in /var/lib/netbird and needs no key;
# a daemon that is down, logged out, or whose session expired counts as not
# enrolled for this preflight.
enrolled=0
if has_client_state && command -v netbird >/dev/null \
  && status=$(netbird status 2>/dev/null) \
  && [[ "$status" != *NeedsLogin* && "$status" != *LoginFailed* && "$status" != *SessionExpired* ]]; then
  enrolled=1
fi
if [[ -n "$key_file" ]]; then
  [[ -f "$key_file" && ! -L "$key_file" && "$(stat -c '%U %a' "$key_file")" == 'root 600' ]] \
    || fail "--setup-key-file must name a root-owned 0600 file"
elif [[ "$enrolled" -eq 0 ]]; then
  fail "ts-ops is not enrolled yet: first enrollment needs --setup-key-file"
fi
systemctl is-active --quiet netbird-server.service || fail "install the NetBird manager (install.sh) first"
if ! ip link show wt0 >/dev/null 2>&1; then
  holder=$(ss -Hlnu "sport = :51820" || true)
  [[ -z "$holder" ]] || fail "udp 51820 is already in use: $holder"
fi

if [[ "$dry_run" -eq 1 ]]; then
  if [[ -n "$key_file" ]]; then
    enrollment="enroll ts-ops with the protected setup-key file"
  else
    enrollment="bring the enrolled ts-ops peer up without a setup key"
  fi
  echo "[dry-run] preflight passed; would install and hold netbird=$CLIENT_VERSION, enable IPv4 forwarding and the peer firewall, apply client limits, and $enrollment"
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
# `netbird service install` starts the daemon without enabling it, so enable
# it unconditionally.
systemctl enable netbird.service
if systemctl is-active --quiet netbird.service; then
  systemctl set-property --runtime netbird.service CPUWeight=50 MemoryHigh=128M MemoryMax=192M
else
  systemctl start netbird.service
fi

up_args=(
  --management-url https://netbird.terrascale.tech
  --hostname ts-ops
  --disable-dns
  --disable-client-routes
  --allow-server-ssh=false
  --external-ip-map "$PUBLIC_IP/$PRIVATE_IP"
)
# Log in with a saved identity first; the setup key is only for a peer
# without one or whose login NetBird reports as needed (NeedsLogin or
# SessionExpired). A network failure must not consume the key.
if has_client_state; then
  keyless=0
  netbird up "${up_args[@]}" || keyless=$?
  if ! needs_login; then
    [[ "$keyless" -eq 0 || "$(peer_status)" == *"Management: Connected"* ]] \
      || fail "netbird up could not reconnect the saved identity; the setup key was not used"
    netbird status
    exit 0
  fi
  [[ -n "$key_file" ]] || fail "the saved NetBird identity needs a login: rerun with --setup-key-file"
  echo "install-routing-peer.sh: saved identity needs a login; enrolling with the setup key" >&2
fi
[[ -n "$key_file" ]] || fail "ts-ops has no NetBird identity: first enrollment needs --setup-key-file"
netbird up "${up_args[@]}" --setup-key-file "$key_file"
netbird status
