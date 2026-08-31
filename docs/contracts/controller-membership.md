# Controller membership and the global region directory

- Status: current v2 contract
- Subject root: `ts.orch.v2`
- Implementation: `src/orchestrator/control` and
  `src/orchestrator/protocol`

## Regional membership

Every regional controller owns one renewable KV registration in the region's
bounded runtime bucket under `controller.<instance>`. The record binds:

| Field group | Meaning |
| --- | --- |
| Schema, region, cluster | Contract version and regional scope |
| Instance and session | Stable controller slot and the process that owns it |
| Build and capabilities | Exact build plus sorted capability set |
| Start, observation, expiry | Process age and semantic lease |
| Authority term and revision | Fenced authority observed by the publisher |
| Public key and signature | Identity and signature over the canonical record |

The heartbeat interval is five seconds and the semantic lease is twenty
seconds. Peers do not delete another controller's record. Expiry marks it
stale. Only the owning session may delete its record under the current KV
revision.

## Identity continuity

The first valid record for an instance slot pins that slot's public key while
its lease is live. A different key or session during the live lease is a
conflict. After the lease expires, a replacement process may take over the
slot with a new key through compare-and-swap.

Every update must match its region, cluster, instance, session, key, authority
term, and held KV revision. A live foreign session is never overwritten. An
old term or revision cannot replace a newer record.

## Reader states

Readers classify a slot as healthy, stale, missing, unexpected, wrong-region,
conflicting-session, stale-term, invalid-signature, or malformed. Missing and
stale are observations, not deletion or failover authority.

Controller eligibility combines membership with the live authority claim:

- a live claim, matching term, leadership, and quorum permits mutation;
- a peer's live claim makes the controller read-only;
- quorum loss makes authority uncertain and read-only; and
- an expired, malformed, or stale claim is ineligible.

The mutation boundary rechecks the current authority claim immediately before
an external effect and before acknowledging its control operation.

## Global region directory

Each regional leader publishes an advertisement to the GRU global directory.
The advertisement includes the region, regional cluster, authority term and
revision, sequence, capabilities, health summary, observation time, expiry,
and one or more explicit control endpoints.

Endpoints come from `TS_ORCH_GLOBAL_DIRECTORY_ENDPOINTS`. Enabling publication
without endpoints fails startup. The directory does not invent addresses from
hostnames, routes, or NATS connections.

GRU rejects an advertisement that is malformed, bound to the wrong key,
expired behind a live entry, older by term or sequence, or byte-different at
the same ordering point. Expiry marks the projection stale. It never revokes
regional authority.

The read-only query service publishes the current projection. It has no write
permission on the directory bucket. Service discovery complements the durable
directory and cannot replace it.

## Telemetry

Metrics use bounded region and state labels. They report active, stale,
missing, unexpected, and conflicting controller counts, quorum availability,
leader count, maximum heartbeat age, rejected records, and active or stale
directory entries. Instance, session, peer, and remote-region identifiers are
not metric labels.

## Verification

Tests cover virtual-clock lease transitions, canonical signatures,
compare-and-swap races, stale term rejection, one-controller loss, one-server
loss in R3, directory publisher loss, gateway isolation, reconnect, and
conflicting-session recovery.
