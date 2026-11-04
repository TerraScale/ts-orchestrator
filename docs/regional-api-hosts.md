# Regional API hosts

DNS-only regional A records point to that region's OCI edge. A regional host
or `X-TerraScale-Region-Pin` waits for the local backend during a stop-first
rollout instead of silently failing over to another region. Unpinned global
hosts retain rollout failover. Backend-requested database forwarding and
`Ts-Replay` remain available after the named region receives the request.
When forwarding cannot reach a database's home, a public 421 carrying
`X-TerraBase-Database-Home` also carries `Location` with the full HTTPS retry
URL in that region, preserving the request path and query.

`GET https://api.terrascale.tech/v1/regions/origins` is owned by
the edge. It advertises `{ "regions": [{ "id": "gru", "apiUrl":
"https://gru.api.terrascale.tech" }] }` for the automatically admitted mesh
regions, sorted by ID and cached for five seconds. It needs no credential or
application backend; missing mesh identity returns 503. Consumers such as
ts-status use the advertised origins rather than maintaining DNS-name lists.

The 2026-11-04 mismatch occurred during a TerraBase rollout: generic edge
failover rewrote `gru.api` to `sjc.api`, bypassing the regional-host guard in
TerraBase. DNS and runtime identity were correct.
