#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
source "$here/certificates.sh"

begin "postgres pre-auth from one source"
install -d -m 0700 "$work/pg/edge-certs"
leaf pg.e2e.test "DNS:pg.e2e.test"
cat pg.e2e.test.key pg.e2e.test.pem >"$work/pg/edge-certs/pg.e2e.test"
CGO_ENABLED=0 go -C "$repo" build -trimpath -o "$work/pg-preauth" ./test/e2e/m1/postgres-preauth
sudo unshare -n sh -c 'set -eu
ip link set lo up
ip addr add 10.80.1.1/8 dev lo
ip addr add 10.80.2.1/8 dev lo
ip addr add 10.80.3.1/8 dev lo
ip -6 addr add fd00:c121::1/64 dev lo
i=1
while [ "$i" -le 200 ]; do
	ip -6 addr add "fd00:c120::$(printf %x "$i")"/64 dev lo
	i=$((i + 1))
done
exec "$1" "$2" "$3" "$4"
' sh "$work/pg-preauth" "$work/pg" "$work/ca.pem" pg.e2e.test
end "32 and 200 pre-auth sockets from one source leave another source and an open session querying"
