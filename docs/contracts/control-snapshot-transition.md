# Control snapshot transition design

Status: the end-to-end transition remains design input and is not implemented
or production-qualified. The single-stream snapshot envelope, preliminary
capture, OCI publication, and isolated candidate synchronization have executable
implementations. Their existence does not establish provider or VM qualification.
The original transition design was audited on
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
`src/orchestrator/restoredrill/nats_snapshot.go` stores a version-4 USTAR
envelope with exactly two ordered regular files: `manifest.json` and
`stream.snapshot`. The manifest retains the stream name, complete snapshot
request, capture time, snapshot API configuration and stream state, an explicit
consumer inventory, and the inner archive's SHA-256 and size. `stream.snapshot`
contains the exact S2-compressed NATS archive, requested with consumers included and message
checking enabled. The object identity hashes the complete envelope.
`ControlEpoch` is the sole snapshot epoch field and callback; database restore
epochs remain separate. Version 1 lacked consumer inventory; version 2 lacked
source checkpoint evidence; version 3 lacked source record evidence. All are
rejected. There is no bare-archive or
old-field compatibility reader.

The manifest also retains `recordsSha256`, computed from the source's retained
records after transfer. Each record binds its subject, headers, payload, original
timestamp and sequence through deterministic SDK JSON encoding. Source stream
state and configuration must match the snapshot response before the read and
remain unchanged afterward; source creation identity must also remain stable.
Consumer inventory/checkpoints are checked again after the read. Public restore
requires its record digest to match this source digest before candidate evidence
can be accepted. The encoded records are hashed incrementally with a cumulative
bound of eight times the configured snapshot limit. GET permission is limited
to the exact admitted source streams. These checks do not supply a writer fence
or make sequential stream captures an atomic cut.

The configured byte bound covers the complete envelope; the default is 64 MiB,
the maximum configurable bound is 1 GiB, and the manifest is limited to 1 MiB.
The inner decompressed archive is bounded at eight times the configured bound.
Canonical envelope comparison rejects alternate headers, duplicate manifest
fields, extra entries and trailing bytes. Inner validation checks the stream
configuration against `meta.inf`, requires stream metadata/checksum entries,
checks inequalities within the API-reported allocator state, requires a
message block for nonempty or previously allocated streams, and validates the
archived consumer inventory described below. It consumes the compressed stream
to its end. These are structural checks. The validator does not parse message
blocks to reconstruct allocator, message or deletion state. Consumer checkpoint
validation is described below; the public API does not expose the source's
complete per-message pending/redelivery maps for an independent comparison.

The snapshotter inventories consumers through the public names and info APIs
before and after capture. The sorted inventory retains each consumer's name,
creation time, durable name, and memory-storage flag. For file-backed consumers
it also retains a configuration digest, delivered and acknowledgement-floor
consumer/stream sequences, acknowledgement-pending and undelivered counts, and
redelivered-message count. Both observations must match, and their count must
equal the snapshot API's consumer count. Inventory is bounded to 256 consumers
per stream. Changing delivery, acknowledgement or pending state refuses capture;
these observations still do not fence concurrent writers or consumer activity.

The pinned NATS file snapshot omits memory-backed consumers even though the
snapshot API counts them. The envelope explicitly records memory-backed ephemeral
watchers as omitted from the archive. A memory-backed durable consumer refuses
capture because its checkpoint would be lost. Every file-backed consumer must
have exactly its metadata, checksum, and nonempty checkpoint files in the
archive, with matching consumer and durable names and file storage. Unexpected
or missing archived consumers fail verification. Before publication or restore,
`o.dat` is decoded under the pinned NATS v2.14.6 format-2 contract. Unsupported
formats, noncanonical/truncated varints, duplicate stream entries, invalid
sequence ranges, timestamp overflow and trailing bytes are rejected. Each file
is bounded to 64 MiB and each pending/redelivery collection to 1,048,576 entries,
also bounded by the actual remaining bytes before map allocation. Its delivered
and acknowledgement-floor sequences and collection counts must match the
retained source API checkpoint. This checks every encoded entry structurally;
it does not independently establish each entry's live source identity or timer.
Public restore also
requires each persistent consumer's configuration digest and checkpoint values
to equal the retained source evidence, before comparing target and reference
restores. Ephemeral watcher recreation also remains a
destination runtime responsibility.

A successful first upload requires PUT, matching HEAD digest/size with a
nonempty ETag, and GET of the exact uploaded bytes. A retry reads and validates
the stored envelope, requires its request to match exactly, and returns the
original capture time. Missing, corrupt or unreadable bodies fail even when
HEAD claims success. The returned snapshot identity therefore describes a
verified stored envelope, not merely an acknowledged upload.

The snapshot client validates the pinned server's chunk protocol before
publishing an acknowledgement. Full 1 MiB chunks require the exact stream,
one stable 22-character nonce, matching byte count, and increasing index in
`$JS.SNAPSHOT.ACK.<stream>.<nonce>.<bytes>.<index>`. A short final chunk has no
reply. Completion after full chunks requires status 204; small snapshots end
with an empty message without headers. Error statuses, reply substitution,
changed nonces, malformed counters, and data after a short tail fail before
an object is published. Envelope validation remains a separate requirement.

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
envelope to NATS is incorrect. The preliminary restore worker described below
supplies isolated verification copies; it is not an executable production
transition.

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
| `src/orchestrator/initialgrant/proof.go` | `RetireForReplacement` durably retires an initial launch when replacing it with a non-initial launch. | Keep this retirement invariant. Pre-admit capture, then stop and seal the original store before opening a separate capture copy. |
| `src/orchestrator/initialcontrol/runtime.go` | Runs optional owner-admitted preliminary capture while GRU is live. `supervise` detects retirement and closes the initial runtime and embedded broker. | Keep retirement shutdown. A separate restricted final-capture launch must use a verified copy of the stopped store; that lifecycle does not exist today. |
| `src/orchestrator/initialcontrol/broker.go` | The admitted initial broker is standalone and forbids routes and a system account. | Prepare a separately admitted cluster with a fresh GRU destination directory. Do not widen the initial broker's grant or reuse its standalone directory as cluster state. |
| `src/orchestrator/bootstrap/nats_control_mutations.go` | Replica changes require a live, exact target lease and separately promote admitted consumers. | Add a separate finite transition-grant path for declared storage promotion. Keep ordinary mutation guards unchanged; start ordinary election only after verified R3. |

The planned admission architecture is asymmetric. SFO and FRA have no
regional runtime lease at first boot; GRU runtime commands cannot authorize
cross-Region manifest changes. Their broker-preparation component must be in
each host's first owner-signed initial manifest. The existing local chain is
`cmd/ts-node/bootstrap_startup.go:activateTsNodeBeforeNATS` →
`hostbootstrap.RunLocalBootstrap` →
`hostagent.OpenLocalBootstrap`. It uses that host's existing journal and zero
local epoch floor without connecting to NATS. GRU's capture replacement is
instead admitted through its live GRU runtime-signed `ApplyManifest` command.
Existing bootstrap commands permit only exact initial drain/deploy/release;
this design does not add general bootstrap-authorized `ApplyManifest`.

A finite, domain-separated owner-signed storage transition grant will bridge
the source shutdown. `controltransition` now defines and verifies the immutable
owner-signed plan, and `nodeauthority` can pin that agreement in the existing
private host journal. These APIs do not execute phases or grant storage effects.
Local file intake now pins plans from the original signed source/candidate
configuration using the bootstrap owner key. Remote transfer, the phase receipt
protocol, and privileged phase composition remain unimplemented. End-to-end verification must use the
existing ts-node `bootstrapPublicKeyFile`, together with the original verified
`bootstrapGrantFile`; the VM image currently provisions the public key at
`/etc/terrascale/ts-node-bootstrap/authority.pem` with mode `0400`. The key is
independent of runtime command keys. GRU's `initialgrant` proof publication is
not a generic destination trust root. The owner private key stays off-host.

Binding must be noncircular: component configurations reference a transition
ID and an exact grant delivery location, not a grant embedded in its own
manifest. The separate grant signs the already prepared manifest hashes and
original bootstrap-grant digests. The trusted host executor verifies and pins
that grant once in the existing host journal. If final identities become known
only after initial provisioning, the initial signed configuration authorizes
reading one bounded grant at that exact location; the source cannot retire
until all hosts have pinned the same completed transition. The local document-read and plan-pin path is implemented through the signed
`storageTransition` configuration. Remote transfer and the complete preparation
barrier remain unfinished.

The grant binds the estate/transition identity, original source admission and
store scope, exact destination hosts and named peers, certificates and receipt
signer keys, source/capture/destination directories, both accounts and the full
stream/consumer inventory, prepared and final activation manifest hashes,
accepted election floors, topology epochs, object locations, transfer bounds
and an expiration. Its closed roles permit only capture, broker preparation,
restoration and promotion to exactly R3. Receipt keys are separate host-held
keys pinned by the grant. Grant possession does not permit ordinary application
mutations, an R1 election, arbitrary host manifests or customer admission.

Typed local recovery must run before NATS dialing and before the existing
bootstrap runner returns for an already admitted runtime host. It resumes only
the pinned transition phases within the grant's lifetime, under existing
receiver/journal ownership. It never calls `AdmitBootstrap` after a runtime
epoch or treats an old runtime lease as fresh. Ordinary pending commands retain
their fresh-authorization requirement. Expiration refuses unfinished effects;
it cannot restore the old authoritative R1. Completed runtime service uses
ordinary authority, not the expired transition grant.

Raw NATS snapshot permission is not a read-only capability. In the pinned
server, `jsStreamSnapshotRequest` checks that `deliver_subject` is a valid
publish subject, then `streamSnapshot` publishes archive chunks internally
to that subject. A client's publish allowlist does not constrain this request
field. Do not issue candidate-held source-account snapshot credentials on the
assumption that denying ordinary publication makes them nonmutating.
The proposed snapshot-reader fields and generated credentials were removed.
Existing signed source configurations retain their original rights.

The optional source-owned preliminary worker in `initialcontrol` keeps its
explicitly admitted privileged credentials on GRU. It accepts a bounded,
owner-signed request from the signed configuration's root-owned request file.
Verification uses the original initial admission's owner key. The request binds
the original grant, source node, store scope, profile, both accounts and their
complete stream inventory, exact live global control epoch, and finite dates.
It cannot select NATS reply or delivery subjects. The worker chooses its own
snapshot inbox and checks the observed stream inventory before and after each
account's capture.

The worker stages immutable envelopes in a separate, bounded local directory
and publishes a source-membership-key-signed preliminary receipt. One signed
request pins that output directory. Identical retries preserve prior artifacts;
another request or a newer global term cannot replace that pin. Capture requires
live initial admission and the exact global leadership term throughout its
bounded execution. It holds the initial admission's mutation lock so retirement
cannot complete while capture is still running. Runtime shutdown cancels and
joins the worker before closing the broker. See
[the preliminary capture guide](../guides/control-preliminary-capture.md) for
configuration, request planning, status, and retry limits.

These sequential snapshots describe a still-running source. They do not fence
writers or establish an atomic final cut. `plan-preliminary-transfer` signs an
immutable scope for completed capture bytes, exact GRU/SFO/FRA OCI destinations,
and the original SFO/FRA preparations. Separate finite authorizations admit
source publication and each candidate's preliminary download and restore.
The historical capture epoch remains in every archive. Publication can resume
under renewed upload authority for the same scope and a nonregressing live
global epoch, without recapturing or relabeling those bytes.

The optional initial source publication worker observes exact bucket ownership,
journals provider mutations in GRU's admitted `ORCH_OPERATIONS` store, verifies
remote bytes, and publishes the source-signed publication receipt to all three
destinations. Candidates read their own regional bucket through separately
admitted instance-principal identity. They do not receive the source capture
credentials or need a source-broker status request to read the publication.
The source publication journal still resides on the live source; this is not
the post-retirement mutation or recovery protocol.

An admitted candidate restores each archive into a persistent local target and
a separate temporary reference broker, with account isolation and no network
listeners, routes, authority workers, or membership publication. Both brokers
stop before its signed preliminary receipt is published. Comparing those two
restores proves consistency with the same archive. It does not independently
prove equality to the live source API's consumer checkpoints or a final cut.
Reference preparation publishes its scope pin atomically before starting the
broker. Recovery accepts an empty reference directory or validated temporary
scope-write files when the pin is absent. It retains unrecognized files,
unsafe temporary files, and conflicting committed pins. OCI object metadata
uses bare SHA-256 hex; comparison with signed artifact digests removes the
artifact contract's `sha256:` prefix.
See [the transfer guide](../guides/control-preliminary-transfer.md) for the
actual request and material flow. The full storage transition grant,
post-retirement capture, authoritative destination activation, and R3 readiness
remain separate work.

The required durable order is:

1. Prepare the signed manifests, separately signed grant and control action
   intent. Admit GRU through its live local authority and SFO/FRA through their
   initial local bootstrap. Pin the grant and collect authenticated durable
   preparation receipts from every destination before source retirement.
   Bind actual OCI ownership observations when available; do not invent
   instance identifiers before provider creation. A retry resumes this same
   transition and cannot replace its identity or accepted inventory.

2. Start the SFO/FRA candidates and synchronize them as required by `GOAL.md`.
   Verify identity, storage and health before the final cut. These observations
   are preliminary because GRU can still advance; they cannot replace final
   source inventory and checkpoint evidence. Keep ordinary authority workers
   and customer admission closed on the transitional destination storage.
   Stage and verify preliminary snapshot objects under separate transition
   keys. The standalone source has no admitted route/leaf connection to those
   candidates; declaring a mirror does not create that transport. Keep staged
   preliminary copies separate from the authoritative destination namespace,
   so final restoration never needs to overwrite a provisional stream. Name
   the actual GRU destination host in the grant and respect one orchestrator
   process per host; preparation cannot assume a second concurrent process on
   the source host.

3. Persist source retirement under the existing verified host command. Refuse
   old managed launches, quiesce admitted local effects and wait for the source
   service and embedded broker to stop fully. Shutdown closes all seed,
   participant and provisioner client access; a local guard alone cannot fence
   those remote clients. Persist the stop evidence, seal the original store,
   and record its digest. Preserve the original directory unchanged thereafter.
   A crash before a receipt requires observation of the existing effect.

4. Make and durably verify a bounded copy in the grant's distinct capture
   directory. Launch an embedded broker only on that copy, with all old NKeys
   removed and dedicated identities restricted to inventory/info/snapshot
   requests, snapshot chunk acknowledgements and reply subscriptions. Compose
   no provisioning, membership, election or application workers. The trusted
   host owns stop/seal/copy effects; the capture service cannot reopen the
   original source as an authoritative R1.

5. Capture every admitted stream in both account namespaces, including KV,
   object stores and durable consumers. Persist verified envelopes and a
   source-host-signed receipt binding the grant, retirement, original store
   digest, inventory, archive identities, checkpoints and accepted epoch
   floors. Reopening the copy still runs NATS TTL and retention machinery.
   Preserving the original bytes does not prove envelope equivalence to the
   final cut: compare the captured/recovered state against source evidence and
   refuse completion if expiry or insufficient evidence prevents that proof.
   Sequential archives do not automatically form an atomic application cut.

6. Resume the admitted destination broker preparation without a new source
   lease. Require the source retirement/capture receipt, exact named cluster,
   mutually authenticated routes, isolated accounts, bounded file storage and
   healthy metadata membership. Open only the grant's restricted restoration
   capabilities. A listening socket or `AccountInfo` response does not prove
   restore placement readiness. Use independent durable receipt reads for
   progress; polling host status through the stopped source broker cannot be
   the completion gate in `NATSControlRuntime.applyHandoff`.

7. Restore into the fresh destination cluster as temporary R1 streams placed
   on GRU, then remove temporary placement using the admitted configuration.
   Persist per-stream receipts with archive digest, original/restored metadata
   and verified records, allocator/deletion state and checkpoints. Verify an
   existing restored stream on retry; never delete it to force a retry. The
   finite transition capability permits only these declared storage effects.
   No ordinary lease or application writer runs on this transitional R1.

8. Promote every admitted stream and durable consumer to R3 through the
   separate grant-guarded storage path. Wait for each stream's exact current
   peer assignment before promoting its consumers; prove their assignments and
   preserved state independently. Keep ordinary lease-based mutation guards
   unchanged. Persist a quorum receipt only after the complete inventory has
   passed, including exact current GRU/SFO/FRA placement and nonregressing
   accepted floors. A topology epoch is not an election term.

9. Only after verified R3 and source retirement, start the admitted ordinary
   authority coordinator. Require its actual election above the captured
   accepted source/restored floors while preserving host journal history.
   The grant authorizes this gated launch; it does not fabricate an election
   lease. Activate the final runtime manifests under the admitted phase gates
   and normal target authority. Keep customer admission closed.

10. Verify regional/global readiness and a new committed write and
    acknowledgement with one replica absent, then recovery. Take and verify
    the post-transition snapshot. Prove old seed/bootstrap credentials fail
    authentication and old launches/commands cannot mutate. Revoke temporary
    transition credentials and durably mark the grant consumed on every host.
    Record permanent R3 and completion only after these receipts exist.
    Customer admission still depends on all remaining production gates.

Every receipt must bind the same grant and its immediate predecessor. Reject
omitted accounts, duplicate streams, unexpected consumers, altered archives,
changed identities and conflicting receipts. Existing control action and
host command journals retain authority through source shutdown; signed object
receipts provide independently readable evidence, not another master. The private
plan pin exists; phase journal record types, privileged phase execution and the pre-NATS recovery composition
remain to be implemented and crash-tested. Neither the current handoff loop nor
the single-stream snapshot transport already supplies this architecture.

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
