#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$here/certificates.sh"

begin "regional path through a second edge in its own network namespace"
install -d -m 0700 "$work/regional/edge-certs"
for host in regional.e2e.test upgrade.e2e.test; do
	leaf "$host" "DNS:$host"
	cat "$host.key" "$host.pem" >"$work/regional/edge-certs/$host"
done
bash "$here/regional/peers.sh" "$work"
sudo unshare -n sh -c 'ip link set lo up && exec "$0" "$@"' "$(dirname "$bin")/regional" "$work/regional" "$work/ca.pem" regional.e2e.test upgrade.e2e.test
end "regional edge -> REST, two WebSockets, a drain with both open, REST after it, an upload after a backend's half-close"
