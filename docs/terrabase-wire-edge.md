# TerraBase wire TLS edge

Every region serves `api.terrascale.tech:7464` and its own regional API hostname
with direct TLS and the edge's existing ACME certificates. No ALPN is required.
After TLS terminates, the edge forwards binary frames unchanged to the local
private listener. It does not add the Postgres PROXY header. Unknown SNI and
plaintext connections are rejected before connecting to TerraBase.

The TerraBase service declares `wire.port=7465`, matching its existing
`TerraBaseOptions.WirePort` through `TERRABASE_WIRE_PORT=7465`. The public edge
owns 7464. Private port 7465 stays blocked externally, like Postgres backend 6432.

## Automatic releases and service rollout (FR1)

No release has a manual prerequisite. Each public protocol starts and retries
independently. A bind failure logs the affected protocol and leaves the others
serving. Prometheus host scrapes include `ts_orch_edge_listener_ready` with four
fixed protocol values; `EdgeListenerUnavailable` alerts after one minute.

Wire activates only after a TCP readiness probe confirms its configured private
backend. Missing routes, unavailable private listeners and an occupied public
7464 leave wire down while HTTP, HTTPS and Postgres continue. Readiness is
rechecked every five seconds, and wire automatically recovers after either
release order. Its exact host firewall ACCEPT rule is withdrawn while blocked
and opened only after the edge owns the public TLS socket, keeping a legacy
native plaintext listener private.

FR1 rolls the merged orchestrator release through the normal automatic path.
Update each region's preserved live TerraBase declaration with
`env.TERRABASE_WIRE_PORT=7465` and `wire: {"port":7465,
"hostname":"api.terrascale.tech"}` through the normal gated service rollout.
Preserve live images, secrets and resources; never apply the example's stale
image or secret references. Either component can roll first safely.

After local TLS works, FR1 reconciles public NSG TCP7464 and verifies certificate
chain and hostname from delta on every regional public IP, with
`api.terrascale.tech` as SNI. Keep private7465 blocked. Recheck Postgres
verify-full on5432. COS routes the public handshake evidence to RT6.

No data format change, wipe, new credentials or paid service is needed.
