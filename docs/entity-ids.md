# Entity IDs (TS-754)

Entity IDs are plain, uppercase, 26-character Crockford ULIDs. Generate new
identities with `internal/entityid.New`; its maintained `oklog/ulid/v2` entropy
reader is cryptographic, shared and synchronized, and increases within a
millisecond. Validate inbound identities with `entityid.Valid` or `Parse`.
Prefixes, UUID entity IDs, lowercase spellings, overflow and the zero ID are
rejected.

Managed NetBird rollout, transaction, journal-operation and command IDs use
ULIDs too. Bootstrap ownership is an explicit persisted boolean, never an ID
prefix; command retries derive their own action-scoped ULID. NetBird
provider-assigned peer/group IDs and setup-key secrets retain their native
external contracts.

Stable operational keys use domain-separated `entityid.Derive` so a retried
operation addresses the same record. Domain and values are length-framed before
hashing, including values containing NUL. These have timestamp zero and carry no
creation-time claim. They are not customer document identities or a substitute
for TerraBase's atomic uniqueness guarantees. Entity keys in NATS KV have no
type prefix; machines have their own `TS_MACHINES` bucket alongside `TS_APPS`
and `TS_MACHINE_STATUS`.
App-name/ULID lookup addresses (`<app-name>.<machine-ULID>`) live alongside
primary machine records in `TS_MACHINES`; they are lookup references, not
entity IDs. App-specific listings remain server-filtered. A single stream
snapshot and object upload capture both primary records and their index, so
independent upload failures cannot split the recovery point. The index is
written before machine creation and removed after machine deletion; interrupted
writes may leave harmless empty lookups. Deletes use index revisions to preserve
concurrent writers. Startup rejects historical app records and incomplete
inventory; it never repairs or silently exposes partial state.

Node names remain `ts-<region>-<n>`. Region/role labels, OCI resource IDs, OS and
filesystem UUIDs, certificate/configuration SHA-256 fingerprints, artifact
digests and cryptographic secrets/nonces retain their native formats. Local
signed-admission cluster tokens and member incarnations are nonzero
128-bit lowercase hex; tenant, database and member entity IDs are ULIDs.
These admission fields are distinct from live gRPC origin identity bytes.
Process, terminal and host-request nonces use cryptographic random bytes.
A TerraBase document's key owns its identity; its payload does not add a second
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
   `TS_DELIVERY_OPERATIONS`, `TS_PLACEMENT_STATE`, `TS_STORAGE_USAGE`,
   `TS_REGION_LIFECYCLE` and entity-bearing control-log/release-channel records.
   In `TS_CONTROL_LOG`, inventory retained authority leases and owner/transition
   references, barriers, lifecycle pending intents/approvals and NetBird
   journals/commands with their dependent effect/fencing records. Verify signed
   bootstrap configuration and material, global directory records, object-store heads,
   snapshots and backups too: none may restore old entity references. These
   are inventory candidates, not verified live deletion targets.
   Include retained desired-release generations and active-rollout slots,
   node-operation/fence records, OCI ownership journals and consumed permits,
   and both rollout step/reply boards and signed health proofs. Include retained
   decision-log records,
   disabled/revoked enrollment grants and terminal tombstones, first-format
   controller grants (pending, closed and consumed) and local initializer
   attempt/consumption files. Reset these with the affected volumes and signed
   placement/member records, never independently while old writers can run.
   Stop NetBird workers and rollback timers before resetting affected local
   managed transaction journals, backup directories, worker ledgers and staged
   spool command/result/status files; preserve the live mesh and its external
   peer identities. Fresh signed enrollment policy must authorize only intended
   current instances; wiping tombstones does not authorize revoked nodes.
   Inspect retained, retired and restore volumes and their provider create-key tags; affected old resources must be
   deleted, never adopted through an old tag or rewritten in place.
   Inventory and delete affected controller-created OCI volume backups with
   old create-key tags, including orphan backups whose source volume is gone.
   Verify local pending activations, proofs, watchdogs, retained artifacts,
   signed release/update receipts and delegations, accepted image receipts and
   their root-signed pinned admission manifests, and retained material
   receipts/configuration before deletion. Replace required signed inputs with
   freshly qualified current-format material.
4. Restart against fresh state and current signed bootstrap configuration on
   the existing cell. Preserve OCI instances, node names, NATS membership and
   routes; do not re-found the cell. Recreate management bindings and service
   keys with bootstrap actor `01M4EB0GDPPHGJPPVY77EMZQKT`, writing secrets
   directly to protected configuration. Sessions and old tokens may expire.
   This is a coordinated direct binary installation with old controllers and
   hosts stopped/fenced, not an ordinary rolling self-update: old relays,
   watchdogs and receipt/proof verifiers cannot deliver or authorize this
   first cutover. Start only current-format writers. Fresh-state startup and
   re-enrollment must recreate the cleared system/operational records; a
   reset must not depend on restoring an old snapshot or resuming an old
   rollout. Normal rolling updates resume after the clean cutover qualifies.
5. Verify readiness, a new release/rollout, host re-enrollment and a document
   create/read through the live consumers. Record exact deleted targets and
   validation evidence in the PR before declaring the cutover complete.

Production data deleted by this change: **none yet**. Compatible live
dependencies and exact-target verification are prerequisites for deletion.
