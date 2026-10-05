#!/usr/bin/env bash
# Enroll or restart this host's operator automation peer: a dedicated NetBird
# client in a podman container (host network, own state directory, interface
# and WireGuard port) in group ops-automation, which may only open NetBird SSH
# to gru-servers. Other VPNs and the host resolver stay untouched: legacy
# routing adds no ip rules, and NetBird DNS rewrites only the container's
# resolv.conf. See deploy/netbird/README.md#operator-automation-peer.
set -euo pipefail

NAME=ts-netbird-ops
# Its netbird binary equals the 0.79.0 release pinned in deploy/image.
IMAGE=docker.io/netbirdio/netbird:0.79.0@sha256:3014b46532d6aa3f0512220c4dc589f757379ece0279c7bede9a8a7aad1529f0
STATE=/var/lib/ts-netbird-ops
CREATE=(--name "$NAME" --network host --restart always
  --cap-add NET_ADMIN --cap-add NET_RAW --cap-add BPF --device /dev/net/tun
  -e NB_DISABLE_CUSTOM_ROUTING=true -v "$STATE:/var/lib/netbird"
  --entrypoint /usr/local/bin/netbird "$IMAGE" service run --log-file console)
UP=(up --management-url https://netbird.terrascale.tech --hostname "$(hostname -s)-ops"
  --interface-name wt-tsops --wireguard-port 51821 --block-inbound
  --disable-client-routes --disable-server-routes --ssh-jwt-cache-ttl 300 --no-browser)

usage() {
  echo "Usage: operator-peer.sh [--setup-key-file FILE]" >&2
  echo "First enrollment needs the one-off ops-automation setup key; re-runs keep the peer's identity." >&2
  exit 2
}

key_file=""
case "$#:${1:-}" in
  0:) ;;
  2:--setup-key-file) key_file=$2 ;;
  *) usage ;;
esac
[[ $EUID -eq 0 ]] || {
  echo "operator-peer.sh must run as root" >&2
  exit 1
}
for tool in podman jq; do
  command -v "$tool" >/dev/null || {
    echo "operator-peer.sh needs $tool" >&2
    exit 1
  }
done

# The state holds the peer's WireGuard key.
[[ ! -L $STATE ]] || {
  echo "$STATE must not be a symlink" >&2
  exit 1
}
install -d -o root -g root -m 0700 "$STATE"
chown root:root "$STATE"
chmod 0700 "$STATE"

# A container created from other arguments is replaced; the state keeps the
# peer's identity.
spec=$(printf '%s\0' "${CREATE[@]}" | sha256sum | cut -d' ' -f1)
if podman container exists "$NAME" &&
  [[ $(podman inspect -f '{{index .Config.Labels "ts-netbird-ops.spec"}}' "$NAME") != "$spec" ]]; then
  podman rm -f "$NAME" >/dev/null
fi
if ! podman container exists "$NAME"; then
  podman create --label "ts-netbird-ops.spec=$spec" "${CREATE[@]}" >/dev/null
fi
podman start "$NAME" >/dev/null

state() { podman exec "$NAME" netbird status --json 2>/dev/null | jq -r '"\(.daemonStatus) \(.management.connected) \(.signal.connected)"'; }
for _ in $(seq 30); do
  current=$(state) && break
  sleep 1
done
case "${current:?NetBird daemon did not answer}" in
  NeedsLogin* | SessionExpired*)
    [[ -n $key_file ]] || {
      echo "$NAME needs login: rerun with --setup-key-file" >&2
      exit 1
    }
    podman exec -i "$NAME" netbird "${UP[@]}" --setup-key-file /dev/stdin <"$key_file" ;;
  *) podman exec "$NAME" netbird "${UP[@]}" ;;
esac
for _ in $(seq 60); do
  [[ $(state) == "Connected true true" ]] && exit 0
  sleep 1
done
echo "$NAME did not connect to management and signal" >&2
exit 1
