# Controller membership and the global cell directory over NATS

- Status: landed contract tranche (TerraScale.Orchestrator#21)
- Subject root: `ts.orch.v2` per the repository `GOAL.md`; the checked-in
  adapter serves the superseded v1 root until that migration lands.
- Source of truth: the C# contracts in `src/TerraScale.Orchestrator/Messaging/`
  (`RegionalRuntimeMembership.cs`, `RegionalRuntimeMembershipRecords.cs`,
  `GlobalCellDirectory.cs`, `GlobalCellDirectoryRuntime.cs`,
  `GlobalCellDirectoryLifecycle.cs`, `ControllerEligibility.cs`).
  This document derives from those types; it adds no rule they do not implement.

## What membership is

Every regional controller owns exactly one renewable KV registration in the
region's bounded `ORCH_RUNTIME` bucket under the deterministic key
`controller.{instance}`. The record binds:

| Field | Meaning |
| --- | --- |
| `SchemaVersion`, `Cell`, `Cluster` | the record's contract version and its regional binding (`orchestrator-control-{cell}`) |
| `Instance`, `SessionId` | the stable instance id and the process session that currently owns the slot |
| `Build`, `Capabilities` | versioned build identity and the sorted, unique capability set |
| `StartedAt`, `ObservedAt`, `LeaseExpiresAt` | process start, observation time, and the semantic lease |
| `AuthorityState`, `IsAuthorityLeader`, `AuthorityEpoch`, `AuthorityRevision` | the fenced authority evidence at observation time |
| `IdentityKeyId`, `IdentityPublicKey`, `IdentitySignature` | the signed identity: a P-256 key whose signature covers every other field |

The heartbeat contract is five seconds with a twenty-second semantic lease
(`RegionalRuntimeMembership.HeartbeatInterval` / `LeaseDuration`). A record is
never deleted by peers: expiry degrades it to stale, and only the owning session
may delete, under its own compare-and-swap revision.

## Signed identity and key continuity

The membership record is self-contained: it carries the public key it claims.
The key identifier is the SHA-256 fingerprint of that key, and the signature
covers the canonical serialization of every other field. A reader verifies the
signature under the embedded key (`RegionalRuntimeMembershipIdentity.Verify`).

Trust is pinned per instance slot by first valid observation: the first
correctly signed record for `controller.{instance}` fixes that instance's
public key, and later records that present a different key are rejected as
invalid signatures **while the previous lease is still live**. When the lease
has fully lapsed, healing may take the slot over with a rotated key — the
takeover signature — so a restarted process is never locked out of its
deterministic slot. Sessions of the same instance keep their key; a session
may not silently change it mid-lease. Until composition persists a per-instance
identity key file (follow-up), each process generates a fresh key, so a restart
heals through the rotation path.

Known limitation (bounded by this tranche): the KV permission model currently
grants every controller write access to all `controller.*` keys, so the pin
protects against later forgery but not against a first-writer spoof. The
follow-up is per-instance subject grants (`$KV.ORCH_RUNTIME.controller.{n}`),
which the development cluster renderer can express today.

Recorded follow-ups owned outside this contract: wiring the eligibility
classification into the runtime mutation gates (composition scope; today the
gates consult the authority snapshot only), documenting
`TS_ORCH_GLOBAL_DIRECTORY_ENDPOINTS` in the steward-owned `docs/architecture/orchestrator.md`
environment-variable reference, persisting a per-instance identity key file in
composition, and the live OTel export path for the conflicting gauge
(observability scope).

## The reader taxonomy

The reader taxonomy distinguishes, in fixed precedence: **healthy**, **stale**,
**missing**, **unexpected**, **wrong-cell** (which doubles as the
wrong-instance guard), **conflicting-session**, **stale-epoch**,
**invalid-signature**, and (structurally) **malformed** records. Classification
consumes the record, the reader's previously observed record for the slot, and
a virtual clock — never the transport. An absent record with a remembered
predecessor is a departed slot (**missing**), never silently healthy. A session
change under a still-live lease is `ConflictingSession`: the KV compare-and-swap
proves the writer owned the revision, so the durable truth is accepted, the
conflict is counted as current, and telemetry exposes it until the surviving
session's next renewal.

## Compare-and-swap mutation and healing

`RegionalRuntimeMembershipMutation.Decide` is the pure policy behind the claim
and healing paths (the heartbeat renewal path compares epoch and revision
inline under its held revision instead — see the eligibility section):

- a publisher may write only the record bound to its own cell, cluster,
  instance, session, and signing key (`RejectWrongBinding` otherwise; a session
  may not change its key mid-flight);
- an empty slot is created (`CreateOwnRecord`), an own live record is renewed
  (`RenewOwnRecord`) under the held KV revision;
- healing takes an expired slot only after the previous semantic lease has
  actually lapsed (`TakeOverExpiredLease`), rotating the signing key with the
  new session so a restarted process is never locked out;
- a live foreign session is held, never overwritten, never deleted
  (`HoldForLiveForeignLease`); deletion is restricted to the owning session
  under its own revision (`MayDeleteCurrentRecord`).

Epoch and revision regression is refused (`RejectStaleEpoch`), which is what
makes duplicate, reordered, delayed, or replayed records inert: they either
match the current record exactly (idempotent duplicate) or lose the ordering
comparison.

## Eligibility from evidence and fencing

`ControllerEligibilityRules.Decide` composes the watched membership health with
the fenced `AuthorityLeaseClaim`: a live claim plus quorum plus leadership is
`MutatingLeader`; a peer's live claim is `ReadOnlyFollower`; a lost regional
quorum makes the controller `ReadOnlyUncertain`; an expired, malformed, or
epoch-fenced claim is `NotEligible`. Transport connectivity is not an input.

**This is a classification contract, not yet a runtime gate.** The runtime's
mutation gates today consult the authority snapshot only: the direct-delivery
and journal paths admit work when the controller is the live leader with
epoch/generation equality (`QueueGroupOwnership` and the admission callbacks in
`NatsRuntime`). "Membership quorum lost → the controller becomes read-only and
holds new mutations" is therefore the **contract target, not wired behavior**:
an isolated region keeps its leader and continues pre-authorized work under the
autonomy rules regardless of this classification. Wiring the classification into
the runtime gates is a composition-scope follow-up. One known gap: unlike
`QueueGroupOwnership`, this decision has no revision-equality input — it checks
epoch and lease liveness, not the KV revision of the accepted authority
generation.

Two intentional divergences between the pure contracts and the runtime paths,
recorded so they are not mistaken for defects:

- The heartbeat renewal path never calls
  `RegionalRuntimeMembershipMutation.Decide`: renewal rewrites the publisher's
  own record under its held compare-and-swap revision, comparing epoch and
  revision inline. `Decide` governs claiming, healing, and the pure-policy
  tests.
- The watcher never produces a `StaleEpoch` classification: NATS KV delivers
  per-key updates in revision order, so a regressing epoch cannot arrive after
  a newer one through the watch. Records replayed through other paths are still
  classified stale-epoch by the pure reader.

## The global cell directory

Each cell's current authority leader publishes an advertisement into the
GRU-owned `GLOBAL_CELLS` bucket under `cell.{cell}` every five seconds with a
twenty-second semantic lease. The advertisement binds the cell, the regional
cluster identity, the fenced authority identity/epoch/revision and an ordered
sequence, capabilities, the health summary, the observation time, the semantic
lease, and the cell's advertised **control endpoints** (one to eight validated
absolute URIs with explicit ports; supplied by composition, never invented).

Endpoints are publication input, not derived state: composition supplies them
through `TS_ORCH_GLOBAL_DIRECTORY_ENDPOINTS` (comma- or semicolon-separated;
also `globalDirectoryEndpoints` in the bootstrap configuration file). A
composition that enables publishing without endpoints fails fast at directory
start — before any connection is created — and the supervised lifecycle keeps
retrying without making regional control depend on the directory.

Readers converge the durable KV projection through `GlobalCellDirectory`,
which rejects advertisements that are malformed, unbound to their durable key,
expired when a live one exists, older by epoch/revision/sequence, or identical
in order but different in content. Expiry marks a projection stale; it never
revokes regional authority. The NATS read-only query service
(`ts.orch.v2.global.query.cells`, queue group `ts-orch-global-cell-directory`)
serves the snapshot and holds no write permission on the bucket — service
discovery complements, and never replaces, the durable membership truth.

## Telemetry

`OrchestratorTelemetry` exports bounded aggregates only: membership
active/stale/missing/unexpected/conflicting controller counts, quorum
availability, leader count, maximum heartbeat age, rejected records, and
directory active/stale cell counts with rejected advertisements. The
conflicting-session count is a **current gauge** — each slot's live record
classified against its immediately preceding observation, bounded by the slot
count — never a lifetime counter, so it cannot outgrow the projection it
describes. Labels are bounded enums (cell, condition, state) — no instance,
peer, or remote-cell labels exist.

## Evidence lanes

- Pure, virtual-clock: `RegionalRuntimeMembershipTests`,
  `RegionalRuntimeMembershipReaderTests` (including the canonical-material
  exhaustiveness proof), `RegionalRuntimeMembershipMutationTests`,
  `ControllerEligibilityTests`, `GlobalCellDirectoryTests`,
  `GlobalCellDirectoryLifecycleTests`, and the
  `GlobalDirectoryEndpointsConfigurationTests` composition-seam tests.
- Real R3 component lane (one region, three members):
  `NatsControlR3MembershipTests` — multi-instance discovery, one-member loss,
  renewal continuity, and the dead-member leftover-record heal: the live lease
  is held, the lapsed slot heals through the KV compare-and-swap update, and
  two racing healers produce exactly one winner with the loser refused by the
  typed active-lease error. Membership staleness detection, recovery, and the
  current-conflict storm also run inside `NatsCreateNodeOperationJournalTests`
  against real JetStream.
- RF1 gateway lane (GRU/SFO/FRA, one server per region):
  `NatsGatewayR1DirectoryTests` — publisher loss marks the cell stale within the
  semantic lease while the mesh keeps querying the stale projection; a restarted
  publisher recovers the same cell without cross-cell KV access or authority
  loss, and the queue-grouped directory service instances stay horizontally
  distributable. The gateway-loss phase then severs SFO's links and proves
  regional continuity plus cross-mesh failure and heal.

Known RF1 fixture limitation (outside this tranche's write scope): the T-20
gateway fixture's single-server clusters solicit a self-route bound to
`0.0.0.0`, and the route certificate's SANs cover only the loopback and
gateway-network addresses. When the sever/heal network churn drops the
self-route TCP connection, the server's redial fails TLS verification
(`certificate is valid for 127.0.0.1, <gateway-address>, not 0.0.0.0`), which
leaves that region's single-node JetStream meta layer wedged for the remaining
window — core NATS and `$SYS` keep answering. The RF1 directory scenario is
therefore ordered so that no JetStream-dependent assertion runs after a heal;
the fixture's route certificate SAN fix belongs to the gateway-fixture owner.
