# Entity IDs (TS-754)

Entity IDs are plain, uppercase, 26-character Crockford ULIDs. Generate new
identities with `internal/entityid.New`; its maintained `oklog/ulid/v2` entropy
reader is cryptographic, shared and synchronized, and increases within a
millisecond. Validate inbound identities with `entityid.Valid` or `Parse`.
Prefixes, UUID entity IDs, lowercase spellings, overflow and the zero ID are
rejected.

Stable operational keys use domain-separated `entityid.Derive` so a retried
operation addresses the same record. These have timestamp zero and carry no
creation-time claim. They are not customer document identities or a substitute
for TerraBase's atomic uniqueness guarantees. Entity keys in NATS KV have no
type prefix; machines have their own `TS_MACHINES` bucket alongside `TS_APPS`
and `TS_MACHINE_STATUS`.

Node names remain `ts-<region>-<n>`. Region/role labels, OCI resource IDs, OS and
filesystem UUIDs, certificate/configuration SHA-256 fingerprints, artifact
digests and cryptographic secrets/nonces retain their native formats. A
TerraBase document's key owns its identity; its payload does not add a second
`id` field.

## Clean reset

Old IDs are not supported. There is no migration, backfill, ID rewrite,
compatibility shim or dual read/write path. The cutover deletes the affected
data and recreates bootstrap state through the current startup path.

1. Qualify the combined TerraBase ULID and TS-755 schema10 release, compatible
   SDK/auth/dashboard consumers, and this orchestrator release. Keep fleet
   auto-deployment paused until all consumers are ready; never deploy schema9.
2. Verify the actual serving region, host, resolved storage path, bucket/object
   version and KV/stream inventory with protected operator access. Fence old
   writers in every serving region before deleting any data.
3. Delete affected entity data and stale references together. Candidate
   orchestrator inventories include `TS_APPS`, `TS_MACHINES`,
   `TS_MACHINE_STATUS`, `TS_TENANTS`, `TS_VOLUMES`, `TS_ROLLOUTS`,
   `TS_HOST_ENROLLMENT`, `TS_HOST_STATE`, `TS_OCI_OPERATIONS`,
   `TS_DELIVERY_OPERATIONS`, `TS_PLACEMENT_STATE`, `TS_STORAGE_USAGE`, and
   entity-bearing control-log/release-channel records. Verify signed bootstrap
   configuration and material, global directory records, object-store heads,
   snapshots and backups too: none may restore old entity references. These
   are inventory candidates, not verified live deletion targets.
4. Restart against fresh state and current signed bootstrap configuration on
   the existing cell. Preserve OCI instances, node names, NATS membership and
   routes; do not re-found the cell. Recreate management bindings and service
   keys with bootstrap actor `01M4EB0GDPPHGJPPVY77EMZQKT`, writing secrets
   directly to protected configuration. Sessions and old tokens may expire.
5. Verify readiness, a new release/rollout, host re-enrollment and a document
   create/read through the live consumers. Record exact deleted targets and
   validation evidence in the PR before declaring the cutover complete.

Production data deleted by this change: **none yet**. Compatible live
dependencies and exact-target verification are prerequisites for deletion.
