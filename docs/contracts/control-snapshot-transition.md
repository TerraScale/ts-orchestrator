# Control snapshot transition design

Status: the end-to-end transition remains design input and is not implemented
or production-qualified. The single-stream snapshot envelope described below
is implemented. Audited on
2026-09-05 against PR-03 in `GOAL.md`. This document describes the required
end-to-end transition from the temporary GRU standalone R1 to permanent
GRU/SFO/FRA R3. A snapshot transport helper or an optional restore field alone
does not implement this transition.

The permanent test in
`src/orchestrator/initialcontrol/profile_promotion_test.go` establishes content
recovery through public NATS snapshot/restore APIs under controlled conditions.
It does not establish production writer fencing, signed preparation, authority
cutover, or bootstrap credential retirement. See
[the empirical audit](../evidence/nats-snapshot-promotion-audit-2026-09-05.md) and
[its qualifications](../evidence/nats-snapshot-promotion-limits-2026-09-05.md).

The current single-stream transport in
`src/orchestrator/restoredrill/nats_snapshot.go` stores a version-1 USTAR
envelope with exactly two ordered regular files: `manifest.json` and
`stream.snapshot`. The manifest retains the stream name, complete snapshot
request, capture time, snapshot API configuration and stream state, and the
inner archive's SHA-256 and size. `stream.snapshot` contains the exact
S2-compressed NATS archive, requested with consumers included and message
checking enabled. The object identity hashes the complete envelope.
`ControlEpoch` is the sole snapshot epoch field and callback; database restore
epochs remain separate. There is no bare-archive or old-field compatibility
reader.

The configured byte bound covers the complete envelope; the default is 64 MiB,
the maximum configurable bound is 1 GiB, and the manifest is limited to 1 MiB.
The inner decompressed archive is bounded at eight times the configured bound.
Canonical envelope comparison rejects alternate headers, duplicate manifest
fields, extra entries and trailing bytes. Inner validation checks the stream
configuration against `meta.inf`, requires stream metadata/checksum entries,
checks inequalities within the API-reported allocator state, requires a
message block for nonempty or previously allocated streams, and requires
metadata/checksum/state files for the reported number of consumers. It consumes
the compressed stream to its end. These are structural checks. The validator
does not parse message blocks to reconstruct allocator, message or deletion
state, or prove that every API state field matches the archived contents.

A successful first upload requires PUT, matching HEAD digest/size with a
nonempty ETag, and GET of the exact uploaded bytes. A retry reads and validates
the stored envelope, requires its request to match exactly, and returns the
original capture time. Missing, corrupt or unreadable bodies fail even when
HEAD claims success. The returned snapshot identity therefore describes a
verified stored envelope, not merely an acknowledged upload.

Fresh empty streams and purged streams with a nonzero sequence allocator are
supported. `TestNATSSnapshotEmptyStreamsPreserveAllocatorAndConsumer` restores
both through the public NATS API into an independent file-backed broker using
only the envelope's configuration, state and inner archive. It verifies first
and last sequence, durable consumer configuration, delivered/acknowledged
positions, pending counts, the next allocated message and its acknowledged
delivery. Other focused tests exercise nonempty content/checkpoint recovery,
readback failures, missing message or consumer files and trailing data. These
public restore tests cover their fixtures; they do not prove arbitrary
archive state equivalence, clustered restoration or the known consumer
creation-time defect below.

The transport captures one configured stream on one supplied account
connection. It does not discover both control accounts, authorize a complete
inventory, fence writers, publish an atomic multi-stream cut, or compose a
production restore worker. A restore implementation must validate the envelope,
submit its configuration/state to the public restore API, transmit the inner
archive, and compare the recovered records, allocator/deletion state and
consumer checkpoints against the admitted manifest and source evidence.
Envelope acceptance alone cannot satisfy that comparison. Sending the outer
envelope to NATS is incorrect. The private codec and test restore calls are not
an executable production transition.

A separate [single-metadata-seed experiment](../evidence/nats-single-metadata-seed-2026-09-05.md)
did not establish clustered startup with one metadata member on the pinned
server. A self route left the expected metadata size at two without a leader;
a non-JetStream router experiment also failed its readiness gate. This does
not prove every possible clustered bootstrap configuration unsupported. It
provides no verified alternative to the transition work described here.

The current callers expose an ordering gap:

| Caller | Current behavior | Required integration |
|---|---|---|
| `src/orchestrator/bootstrap/control_plane.go` | Journals control actions and schedules candidate synchronization, promotion, quorum verification, and retirement. | Admit the complete transition and persist progress through every storage and authority boundary. The final state must follow verified effects. |
| `src/orchestrator/bootstrap/provider_control_plane.go` | `PromoteGlobalR3` invokes the runtime through the provider mutation path and records runtime evidence in provider state. | Require the durable transition receipts before recording a successful promotion. Provider tags cannot replace storage or fencing evidence. |
| `cmd/orchestrator/bootstrap_control_config.go` | Loads action declarations using an embedded `ControlRuntimeActionPlan`. | Admit the signed preparation and transition declarations, with explicit credentials, identities, bounds, and complete inventory. |
| `src/orchestrator/bootstrap/nats_control_runtime.go` | `Execute` applies all handoffs, creates mirrors, updates replicas, and gathers store checks. `applyHandoff` waits for component readiness. | Separate broker preparation from runtime activation. Capture and restore must occur in the appropriate phases before runtime readiness is required. Update the constructor's manual action-plan clone when adding fields. |
| `src/orchestrator/hostagent/transport.go` | `applyManifest` uses the existing command journal and invokes `initialgrant.RetireForReplacement` before replacement manifest effects. | Bind preparation and activation to the existing signed command and journal authority. Preserve recoverable progress without authorizing the retired launch. |
| `src/orchestrator/initialgrant/proof.go` | `RetireForReplacement` durably retires an initial launch when replacing it with a non-initial launch. | Keep this retirement invariant. A separate capture phase must finish before an effect that stops its only source broker. |
| `src/orchestrator/initialcontrol/runtime.go` | `supervise` detects retirement and closes the initial runtime and embedded broker. | Support an explicitly admitted capture lifecycle that can quiesce writers while retaining the source broker long enough to take the final cut. This lifecycle does not exist today. |
| `src/orchestrator/initialcontrol/broker.go` | The admitted initial broker is standalone and forbids routes and a system account. | Prepare a separately admitted cluster with a fresh GRU destination directory. Do not widen the initial broker's grant or reuse its standalone directory as cluster state. |
| `src/orchestrator/bootstrap/nats_control_mutations.go` | Replica changes require a live, exact target lease and separately promote admitted consumers. | Establish fresh target authority under the transition before ordinary lease-fenced replica mutations can run. A restored expired lease is insufficient. |

Applying the existing full handoff before restoration can wait forever for a
runtime whose authority store has not been restored. Moving restoration after
that handoff does not break the cycle. Retiring the initial launch first also
stops the broker needed by the public snapshot API. The implementation must
resolve both dependencies explicitly.

The required durable order is:

1. Persist the transition intent under the existing control action journal.
   Bind its operation identity, source topology epoch, target epoch, exact
   GRU/SFO/FRA host and server identities, predecessor manifests, signed
   preparation and activation manifests, and distinct source/destination
   directories. Persist the authorized inventory and finite transfer limits.
   A retry resumes this intent; it must not mint a second transition.

2. Prepare the SFO and FRA candidates and synchronize them as required by
   `GOAL.md`. Record what was synchronized and verified before the final cut.
   Candidate observations are preliminary evidence because GRU can still
   advance. They cannot substitute for the final source inventory.

3. Persist and apply a writer fence. Quiesce every application writer to the
   captured accounts, including election renewals, membership, acknowledgements,
   KV updates, and provisioning. Wait for admitted in-flight effects to finish.
   Record receiver and runtime receipts. Keep only the explicitly authorized
   capture capability available. A stopped process, expired client connection,
   or provider tag alone does not prove the fence.

4. Capture the final cut while the source broker is available and writers are
   fenced. Capture every admitted stream in both account namespaces, including
   KV and object-store streams and durable consumers. Use the public snapshot
   API with consumers and message checking. Persist the exact archives and
   their digests with the source inventory and checkpoint evidence. Verify
   durable readback before admitting the cut. Account for server-driven expiry
   and retention during capture; sequential archives are not automatically an
   atomic application cut. The capture protocol must prove a consistent cut
   or reject the observation.

5. Persist source retirement and stop receipts. Prevent the original launch,
   bootstrap provisioners, and prior application credentials from resuming
   writes. Preserve the source directory unchanged. No automatic retry may
   restart it as an authoritative R1. A crash before a receipt requires
   observation of the existing effect, rather than a replacement operation.

6. Activate the signed broker preparation on the three destination hosts.
   Start only the services needed for authenticated cluster formation and
   restoration. Require one named cluster, unique admitted server names,
   mutually authenticated route policy, account isolation, finite file-backed
   storage, and exact healthy metadata membership. A listening socket or
   `AccountInfo` response alone does not establish restore placement readiness.
   Preparation must remain restartable using the existing durable host journal
   after source authority stops; the finite authorization for this is an
   unresolved contract, not permission to bypass live command verification.

7. Restore the admitted archives into the fresh cluster as R1 streams placed
   on GRU, then remove temporary placement using the original configuration.
   Persist each restoration receipt with its archive digest, account, stream,
   original metadata, observed restored metadata, and verified retained state.
   On retry, verify an existing restored stream against that evidence or
   resume a missing restoration. Never delete an existing stream to force a
   retry. Restored bytes remain closed to application writers until the full
   inventory has passed verification.

8. Establish target authority through the admitted transition. Preserve
   accepted epoch floors and all host journal history. The exact one-time
   authority needed to cross the source-stop interval must be specified and
   verified before implementation; neither a copied lease nor desired
   configuration establishes a live election. Keep customer admission and
   ordinary global mutations closed while the topology remains transitional.
   Obtain the fresh lease required by the existing mutation guards without
   reopening unrestricted production R1 authority.

9. Promote every admitted stream and durable consumer to R3 under that
   authority. Verify exact current GRU/SFO/FRA assignments and unchanged
   application state. Updating a stream does not upgrade an explicitly R1
   consumer. Verify acknowledgements and consumer checkpoints independently.
   Persist promotion evidence only after the entire inventory passes.

10. Activate the normal runtime and verify regional and global readiness.
    Prove a new committed write and acknowledgement with one replica absent,
    restore the replica, and verify recovery. Take and verify the required
    post-transition snapshot. Prove bootstrap credentials are rejected by
    authentication, and that old seed commands and launches cannot mutate.
    Record permanent R3 and completion only after these receipts exist.
    Customer admission still depends on all remaining production gates.

Each persisted receipt must bind the same transition intent and its immediate
predecessor. Admission must reject omitted accounts, duplicate stream names,
unexpected consumers, altered archive digests, changed host identities, and
conflicting receipts. The transition journal must survive the interval when
the source is stopped and the target is incomplete. Its storage location,
ownership, and replay authorization need an explicit design using the existing
action and host journals. No new journal should silently become another
authoritative master.

Restoration changes metadata identity. Public clustered restore changes
`StreamInfo.Created`; a receipt must retain both source and observed restored
values. The original server-assigned message timestamps, headers, payloads,
sequence allocation, deletion state, configuration, and consumer checkpoints
remain strict invariants. Stream creation time cannot be treated as an
unchanged source identity.

Pinned NATS v2.14.6 also has a characterized consumer creation metadata
persistence defect. After restore and R3 consumer updates, GRU can persist a
different `Created` value from SFO and FRA. Restart can expose either value
depending on leadership. The permanent regression checks the known disk
divergence and bounds later observations to those captured values. That test
does not authorize a production implementation to accept arbitrary timestamp
changes. Production needs a reviewed identity rule with sufficient durable
evidence, or a qualified vendor fix. Keep this requirement open until one is
proved.

Implementation evidence must cover crashes before and after intent admission,
writer fencing, final-cut publication, source retirement, broker preparation,
each restoration receipt, authority establishment, replica changes, activation,
post-transition snapshot publication, and credential retirement. Tests must
exercise corrupt or incomplete archives, conflicting existing streams,
unexpected inventory, source/destination directory aliasing, stale authority,
partial transfer, expired retained records, one-replica write availability, and
full retained-directory restart. Tests must also prove that a replay cannot
return permanent production control to R1 or make two authorities writable.

The versioned single-stream envelope and the permanent profile test are
implementation references. Neither supplies this transition's source fence,
complete cut, durable restoration receipts, or authority protocol.
The real bootstrap and add-region commands must exercise the integrated flow
on six ready guests before PR-03 can be declared complete.
