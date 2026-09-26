# TerraBase regional managed-Raft plan

**Status: PROPOSED — NOT IMPLEMENTED.** This document describes a staged
implementation direction for an opt-in regional Raft profile. It is not a
production-readiness claim, deployment authorization, or permission to retire
an OCI member. The initial implementation slice is a static three-voter group
with quorum writes and linearizable reads. Scale-down remains disabled in
that slice.

The profile must coexist with current local and leaderless causal document
paths. Selecting managed Raft is explicit per shard and region; loss of quorum
must fail closed, never fall back silently to local-only or causal writes.
Greenfield scope requires no compatibility shim, but current `local_durable`
semantics remain distinct from the proposed Raft success result until a new
implementation deliberately changes the client contract.

## Current verified behavior and gaps

The current client commit service returns `LocalDurableCommit`. It records a
transaction ID, local event, and local commit sequence; it does not include a
remote acknowledgement. The process test checks `durability=local_durable` and
that `received`, `applied`, and `remote_ack` are absent. Point reads query the
local document store. These behaviors apply to the current local/causal paths,
not to the managed-Raft proposal
(`../../terrabase/crates/tb-server/src/document_service.rs:157-223,355-475`,
`../../terrabase/crates/tb-server/src/local_v1_runtime.rs:1018-1100,1425-1508`,
`../../terrabase/crates/tb-server/tests/distributed_client_process.rs:55-85`).

The existing replication sender validates peer identity, authority epoch and
configuration, origin, event sequence, and source high-water. The receiver
persists per-origin contiguous markers and separately reports applied
progress. Those event acknowledgements do not establish a Raft voting
majority or a committed membership change. There is no OpenRaft dependency,
managed-Raft adapter, Raft log/vote storage, or persisted Raft last-applied
index in the reviewed TerraBase manifests and storage source.

Member-control returns HTTP 501 for `/v1/member/serving-proof`,
`/v1/member/drain`, and `/v1/member/drain-status`. Its status response keeps
`serving`, `serving_proof`, and `durable_drain` false even when local health or
readiness is true
(`../../terrabase/crates/tb-server/src/member_control.rs:256-269,338-339`).

Current idempotency expiry pruning advances from the process-local configured
clock in a separate storage transaction. A managed state machine cannot let
each voter choose its own pruning time during replay; expiry progression must
be a replicated, deterministic input
(`../../terrabase/crates/tb-storage/src/native.rs:1698-1701,3005-3045`).

The real Go caller starts placement with a JetStream state store, OCI fleet,
host controller, and admitted artifact resolver (`internal/app/controller.go:190-255`).
The current controller admits one active region with two seats, holds while
waiting for independent serving evidence, moves an observed `StageServing`
member back to `StageAwaitingRuntimeContract`, and holds all retirement
stages until an evidence-driven scale-in path is integrated
(`internal/placement/controller.go:197-204,280-297,580-610`). Go's status
decoder accepts schema 1 only and rejects serving or drain capability bits;
the managed host reporter binds process and mount observations but does not
report Raft commit/applied indices or a native drain receipt
(`internal/host/member_status.go:365-391`,
`internal/host/managed_runtime.go:715-752`). Go placement CAS therefore cannot
certify a committed Raft membership or a safe OCI retirement.

The current managed-member two-VM lane is not Raft proof. Its first recorded
attempt failed at Firecracker drive setup with an invalid resource ID before
guest execution; the next attempt started VMM processes but a VM exited before
guest evidence was ready. Neither produced a passing guest result. The
receipts are `../.qualification/ts-orchestrator/20260926-managed-member-serving/run-01/summary.json`
(SHA-256 `ca9a1a9a512a3b60cde911142b2e12359700ef1a577d0f902071bfe0ade81443`)
and `../.qualification/ts-orchestrator/20260926-managed-member-serving/run-02/summary.json`
(SHA-256 `65d78eb3684a3764c54532492be6fdbf45c37e2c2eb2e2ea0ad4749c5f59470e`).
Even a passing version of that harness would exercise its bounded causal
two-peer path, not Raft election, quorum durability, read barriers, signed
genesis, joint membership, or scale-down.

## Proposed opt-in profile and first slice

Use OpenRaft pinned exactly to `0.9.25`, behind a TerraBase adapter that
isolates OpenRaft's version-specific log-store, vote-store, state-machine,
snapshot, and network APIs. Keep OpenRaft types out of the existing local and
causal document interfaces. Regional NATS/JetStream remains control-plane
infrastructure; it is not a Raft transaction log or a substitute for voter
quorum durability.

The managed profile is one Raft group per shard per region, initially with
three voting members placed in distinct failure domains and a two-voter
majority. It is an explicit profile selected by authenticated configuration.
Without two available voters, writes and linearizable reads fail closed. This
plan does not introduce cross-region synchronous consensus or change the
existing multi-region causal path.

The current Go placement intent is schema 5 and selects a two-seat anti-affine
topology per selected region; this contract does not encode Raft membership.
The proposed signed Raft genesis is a separate versioned authority for the
regional group and voter set. Intent, placement member-state, and native
member-status schema versions are independent counters. Advance a counter
only when its own producer/consumer contract changes, with explicit handling
for older versions.

Bootstrap the static group only from an authenticated, signed genesis that
binds the group/shard/region, the three voter IDs and incarnations, their
authenticated transport identities, the authority generation, and the
initial membership. Every voter must verify the same genesis and its own
member binding before Raft initialization. Later membership requests require
separate authorization and an identity/failure-domain binding; a network
connection or NATS registration alone does not grant voter status. The
genesis format, signing authority, key distribution, and authorization
records still need an assigned owner.

The first slice supports only that static three-voter group:

- Writes commit through OpenRaft only when a majority has durably stored the
  log entry and the leader has applied it to its state machine before replying.
- Reads go through the leader and OpenRaft's versioned linearizable
  read-check/read-barrier, then wait until the leader state machine has applied
  the checked index. Stale follower-local reads are outside this slice.
- There is no learner admission, voter-set change, member drain, Go scale-down,
  automatic downscale, volume detach, or retirement in this slice. The
  three-voter minimum is enforced; loss of quorum is a hold, not a mode switch.
- Local and causal profiles continue to use their current paths and contracts.
  They must not silently enter or impersonate the managed-Raft profile.

## Required Raft durability and state-machine invariants

The adapter targets OpenRaft `0.9.25` specifically. Its log-flush completion
(`LogFlushed`) may be reported only after the underlying log append is durable;
OpenRaft must not count a voter or acknowledge replication before that flush.
`save_vote` must durably sync the vote before returning success so restart
cannot forget a term/vote decision. A database commit, memory buffer, or
successful local RPC send is not by itself a durable voter acknowledgement.

Applying each committed command is deterministic and crash-atomic. One
storage commit advances the document mutation, transaction-ID dedup record and
original result, deterministic expiry floor, and `last_applied` index
together. Applying a membership entry must likewise atomically persist its
effective membership and applied index. Reopen must yield either the complete
old state or the complete new state; it must not expose a document write
without its dedup result or applied index, replay an effect twice, or claim a
membership that was not durably applied.

Snapshots contain the document state, transaction-ID results and dedup
window, expiry floor, last-applied index, and effective membership. Snapshot
creation and installation use an atomic durable publication protocol and
verify the snapshot identity/index before it can replace live state. A
recovered voter cannot serve until its log, snapshot, vote, membership, and
application state agree.

Expiry is driven by a monotonic logical floor carried in replicated state or
commands, not by an independent wall-clock read in each apply callback. All
voters replay the same floor and make the same dedup-expiry decision. The
source of floor advances, accepted skew, and command authorization remain
implementation decisions; the first slice must define and test them before
expiring transaction IDs.

The proposed transport is a separate versioned mTLS gRPC service using the
selected LZ4 framing. It maps certificate identity to the authorized OpenRaft
node ID and group generation, applies explicit size/deadline bounds, and
rejects a peer whose identity, group, or membership is not admitted. Do not
reuse the causal event stream as a Raft transport or treat its `DurableAck` as
a Raft commit acknowledgement.

## Proposed client semantics

Each client transaction carries a stable transaction ID and a canonical,
deterministic command. The leader proposes it through the managed Raft group.
Return success only after OpenRaft confirms the command committed on a durable
majority and the leader has applied it. Persist the transaction ID and exact
result in the same atomic state-machine transaction as the document changes
and applied index.

If the command may have committed but the client response is lost, return
`commit_uncertain` with the same transaction ID when the outcome cannot be
resolved. A retry with that ID queries the replicated dedup result and returns
the original result; it must not issue a second document effect. Do not map
current `local_durable` success to Raft success, and do not report a definite
failure merely because the leader response timed out after a possible commit.

Every managed-profile read uses the leader/read barrier and waits for the
leader's applied index to reach the barrier before reading. If the leader
cannot confirm the barrier or apply state, return unavailable/uncertain rather
than stale data. Any future follower-read mode needs a separate, explicit
consistency contract and is not part of this plan.

## Later membership and retirement slice

Membership changes are not enabled in the static three-voter first slice. A
future add flow admits an authenticated node as a learner only after an
authorized membership request. It must verify that learner has caught up and
applied through the required committed index before promoting it. A blocking
`add_learner` call or low lag metric alone is not proof of application.

The first scale-down qualification is an operator-authorized four-voter to
three-voter transition, never a scale below three:

1. Bind the request to the exact departing voter/incarnation, the four-member
   authority, three named survivors, and their failure domains. Persist an
   idempotent drain command and close application write admission at a
   committed cutoff/barrier index. Resolve in-flight transactions and uncertain
   transaction IDs through that cutoff.
2. Verify each of the three survivors applied through the committed drain
   barrier before changing membership. The receipt must identify the exact
   group, old authority, cutoff, survivor IDs/incarnations/failure domains,
   and observed applied indices. Stale, missing, mismatched, or uncertain
   evidence holds the transition.
3. Use OpenRaft's joint-consensus transition from the four-voter membership to
   the target three voters, then commit and apply the final uniform
   three-voter configuration. Reconcile a lost/ambiguous response from
   persisted Raft membership and indices; do not infer completion from a
   requested transition or a local cached view.
4. Confirm all three final voters applied the drain cutoff and uniform
   membership. Then stop the exact retiring TerraBase process and verify a
   fresh writer-stop result bound to its member incarnation, process identity,
   OCI instance, volume, and attachment. Missing process or storage proof
   blocks retirement even if the new Raft membership committed.
5. Only after the native writer-stop proof and current Go/OCI identity and
   attachment checks may the controller detach the retained volume or
   terminate the exact instance. A Raft membership result, a Go CAS, local
   readiness, or zero lag alone never authorizes an OCI mutation.

The transition needs replay-safe command IDs and explicit recovery at the
drain barrier, joint configuration, uniform configuration, writer stop, and
OCI boundary. A process restart must reconstruct which stage committed and
must never reopen writes on a retiring member. Downscale remains disabled
until these Rust, host, placement, and OCI callers pass the integrated tests.

## Ownership seams

| Owner | Planned responsibility | Existing seam or gap |
| --- | --- | --- |
| TerraBase managed-profile admission | Verify signed genesis and later authorized membership identity before a node joins a regional shard group. | New authenticated profile/genesis path; current member-control has no serving or drain protocol. |
| Rust OpenRaft adapter | Implement the pinned log/vote storage, `LogFlushed` durability, network transport, state-machine apply, and snapshot contracts. | No OpenRaft crate or adapter in the current manifests/source. |
| Rust document state machine | Apply canonical commands, dedup/result, expiry floor, `last_applied`, and membership state atomically; provide leader write and read-barrier semantics. | Current `DocumentService` returns `LocalDurableCommit`; current store has no Raft applied index. |
| Go managed host | Bind an admitted Raft member to its exact process, session, volume, and mount; later relay native writer-stop proof. | Current schema-1 status rejects serving/drain=true and reports process/mount readiness only. |
| Go placement and OCI | Persist authorized membership generation and later consume exact committed membership plus native writer-stop before detach/terminate. | Current schema-4 placement state holds retirement; its CAS does not certify Raft membership. |
| Regional NATS/JetStream | Carry orchestrator control-plane state and placement operations. | It is not a Raft transaction log or a substitute for durable voter majority. |

## Test plan

### Static three-voter first slice

- Verify identical signed genesis and voter identity on all three fault domains;
  reject wrong signer, region, shard, group generation, node ID, incarnation,
  or mTLS certificate.
- Inject process/storage crashes around vote persistence and log append. A
  vote is not acknowledged before `save_vote` is durable; `LogFlushed` does
  not complete before log sync; one durable voter cannot satisfy a two-voter
  quorum.
- Commit with two of three voters and verify leader apply precedes success.
  With only one voter, fail closed. Drop the leader response after a possible
  commit and prove `commit_uncertain` retry returns the same txid result once.
- Test leader/read-barrier reads across concurrent writes and leader changes.
  A stale leader or unavailable quorum cannot return an unchecked local read.
- Crash during document apply and prove document state, dedup result, expiry
  floor, `last_applied`, and applied membership recover atomically. Create,
  install, corrupt, and recover snapshots containing the same complete state.
- Replay expiry commands on voters with different wall clocks and prove the
  replicated logical floor produces identical expiration decisions.
- Run existing local and causal regression suites with the managed profile
  disabled; verify that they remain on their existing contracts and do not
  silently switch to Raft or to local success after a quorum loss.

### Later four-to-three retirement qualification

- Admit a learner with authenticated membership authorization; prove it is
  applied through the required index before promotion. A successful
  `add_learner` response alone does not pass.
- Crash/restart after the drain cutoff, during joint membership, after uniform
  membership, and before/after writer-stop evidence. Reconcile the exact
  persisted state; no duplicate transition or reopened old writer is allowed.
- Partition a voter during 4-to-3. Require three survivors to apply through
  the drain barrier; prove joint then uniform config and final three-voter
  quorum. Unknown joint/uniform outcomes hold for reconciliation.
- Prove that a missing or mismatched survivor, failure domain, generation,
  cutoff, native process identity, volume, or attachment blocks OCI detach and
  termination. Exercise the real Go placement caller, not only boolean helper
  fixtures.

## Open implementation decisions

- Assign the signer and trust-root owner for signed genesis and subsequent
  membership authorization, including how regional node IDs map to mTLS
  certificate identity and OCI failure domains.
- Choose the persistent storage backend and prove its transaction/fsync
  semantics satisfy the OpenRaft 0.9.25 adapter and atomic state-machine
  requirements. The current store has no Raft vote, log, applied-index, or
  membership schema.
- Define who proposes the deterministic expiry-floor command, its monotonic
  advance/skew rules, and how it interacts with transaction-ID retention.
- Freeze the versioned gRPC/mTLS/LZ4 wire limits, key distribution, and
  peer-replacement/revocation rules from the pinned OpenRaft API.
- Define the later four-to-three drain authorization and exact writer-stop
  proof format, and specify the separate producer/consumer contract changes
  required for any future intent, placement member-state, or native
  member-status schema versions.

## Versioned OpenRaft references

Use only OpenRaft `0.9.25` for the initial adapter review. These versioned
references describe the selected API and dynamic-membership model; they do not
show that TerraBase currently implements either:

- [OpenRaft 0.9.25 `Raft` API](https://docs.rs/openraft/0.9.25/openraft/raft/struct.Raft.html)
- [OpenRaft 0.9.25 `RaftLogStorage` trait](https://docs.rs/openraft/0.9.25/openraft/storage/trait.RaftLogStorage.html)
- [OpenRaft 0.9.25 `RaftStateMachine` trait](https://docs.rs/openraft/0.9.25/openraft/storage/trait.RaftStateMachine.html)
- [OpenRaft 0.9.25 `RaftStorage` trait](https://docs.rs/openraft/0.9.25/openraft/storage/trait.RaftStorage.html)
- [OpenRaft 0.9.25 dynamic membership guide](https://docs.rs/openraft/0.9.25/openraft/docs/cluster_control/dynamic_membership/index.html)
- [OpenRaft v0.9.25 release](https://github.com/databendlabs/openraft/releases/tag/v0.9.25)

The adapter's exact trait signatures and call ordering must be checked against
those versioned docs during implementation; do not infer them from newer
OpenRaft releases.
