# TerraBase wire TLS edge

Every region serves `api.terrascale.tech:7464` and its own regional API hostname
with direct TLS and the edge's existing ACME certificates. No ALPN is required.
After TLS terminates, the edge forwards binary frames unchanged to the local
private listener. It does not add the Postgres PROXY header. Unknown SNI and
plaintext connections are rejected before connecting to TerraBase.

The TerraBase service declares `wire.port=7465`, matching its existing
`TerraBaseOptions.WirePort` through `TERRABASE_WIRE_PORT=7465`. The public edge
owns 7464. Private port 7465 stays blocked externally, like Postgres backend 6432.

## First production installation (FR1 only)

The old TerraBase process owns 7464. Deploying the new edge before moving that
process would fail to bind; opening its NSG first would expose plaintext.
Perform this migration in order on all three regions:

1. Preserve each region's current TerraBase image, secrets, resources and live
   service declaration. With the old orchestrator, apply a declaration changing
   only `env.TERRABASE_WIRE_PORT` to `7465`. Omit the new `wire` field, which the
   old orchestrator does not understand. Use the normal gated service rollout.
   Keep public NSG 7464 closed throughout this step.
2. Verify the running release is healthy, the private wire listener moved to
   7465 and no process owns 7464. Confirm public 7465 remains blocked. Existing
   HTTP and Postgres paths must remain healthy.
3. Roll the new merged orchestrator SHA through the release owner. Apply each
   region's preserved live declaration with `wire: {"port":7465,
   "hostname":"api.terrascale.tech"}` added. Do not replace a live declaration
   with the repository's example image or secret references. Route sync adds
   both the global hostname and `<region>.api.terrascale.tech` automatically.
4. Verify local :7464 TLS with SNI `api.terrascale.tech`, then open the public
   NSG TCP 7464 using the existing host-network reconciler. Its desired rules
   include 7464; they exclude private 7465.
5. From delta, verify certificate chain and hostname on each region's public IP
   at 7464, using `api.terrascale.tech` as SNI. Recheck Postgres verify-full on
   5432. Give the handshake evidence to COS for routing to RT6.

No data format change, wipe, new credentials or paid service is needed. After
this initial migration, the service declaration preserves the private listener
port through ordinary releases.
