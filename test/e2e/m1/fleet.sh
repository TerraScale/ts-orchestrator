#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$here/certificates.sh"

begin "edge fleet: six hosts in three regions, each in its own network namespace"
install -d -m 0700 "$work/regional/edge-certs"
for host in dash.e2e.test api.e2e.test auth.e2e.test pg.e2e.test netbird.terrascale.tech gru.mesh.terrascale.tech sjc.mesh.terrascale.tech fra.mesh.terrascale.tech; do
	leaf "$host" "DNS:$host"
	cat "$host.key" "$host.pem" >"$work/regional/edge-certs/$host"
done
SSL_CERT_FILE="$work/ca.pem" bash "$here/regional/peers.sh" "$work" fleet
end "edge fleet -> signed inventory, peer routing, main's local path without a ready peer"
