#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$here/certificates.sh"

begin "public edge abuse limits"
install -d -m 0700 "$work/pg/edge-certs"
leaf pg.e2e.test "DNS:pg.e2e.test"
cat pg.e2e.test.key pg.e2e.test.pem >"$work/pg/edge-certs/pg.e2e.test"
CGO_ENABLED=0 go -C "$repo" build -trimpath -o "$work/edge-limits" ./test/e2e/m1/postgres-preauth
sudo unshare -n sh -c 'set -eu
ip link set lo up
ip addr add 198.18.1.1/15 dev lo
ip addr add 198.18.2.1/15 dev lo
ip addr add 10.80.1.1/8 dev lo
exec "$1" "$2" "$3" "$4" limits
' sh "$work/edge-limits" "$work/pg" "$work/ca.pem" pg.e2e.test
end "source isolation, peer hop, session idle, slow body, spool and WebSocket budgets"
