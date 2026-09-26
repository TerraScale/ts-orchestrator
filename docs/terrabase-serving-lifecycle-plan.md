# TerraBase serving and retirement lifecycle plan

**Status: PROPOSED — NOT IMPLEMENTED.** This is an implementation brief for
distributed write acknowledgement, serving evidence, member drain, and
authority succession. It does not authorize a deployment or claim that a
member is currently safe to retire. The goal is greenfield behavior; no
backward-compatibility promise is required.

The current local-v1 client contract is still distinct: a successful
`local_durable` result means that the local document owner crossed its local
durability barrier. It does not mean that another member durably received or
applied the write. A new distributed-serving contract must state its own
versioned success and uncertainty semantics. Do not reinterpret local
readiness, a process report, a zero-lag gauge, or a local-v1 commit as serving
or retirement proof.

## Verified behavior in the current source

Rust member-control dispatch returns HTTP 501 for
`/v1/member/serving-proof`, `/v1/member/drain`, and
`/v1/member/drain-status`. The existing `/v1/member/status` response reports
local health/readiness but sets `serving`, `serving_proof`, and `durable_drain`
to false (`../../terrabase/crates/tb-server/src/member_control.rs:256-269,338-339`).

The replication sender validates Welcome and ACK peer identity, membership
epoch, configuration, origin, event sequence, and local source high-water. Its
observed durable and applied progress is held in a connection's `StreamState`;
it is not a durable sender-side receipt keyed to a client transaction. The
receiver does persist contiguous journal markers and recovers them on open.
Distributed document apply also scopes durable and applied frontiers to the
authenticated origin and installed epoch/configuration. The replication server
sends a durable acknowledgement after the verified event is received and the
receiver's local durability is confirmed; application progress is reported
separately (`../../terrabase/crates/tb-server/src/replication_sender.rs:420-525,538-563,612-642`,
`../../terrabase/crates/tb-replication/src/journal.rs:335-337,403-470,540-567`,
`../../terrabase/crates/tb-document/src/distributed_apply.rs:260-325`,
`../../terrabase/crates/tb-server/src/replication_server.rs:836-881,1360-1425,1860-1925,2073-2096`).

The client commit path returns `LocalDurableCommit`; its type contains a local
transaction ID, event, and local commit sequence, with no remote receipt. The
process test asserts `durability=local_durable` and absence of `received`,
`applied`, and `remote_ack`. Existing `commit_uncertain` coverage exercises an
uncertain local storage commit and restart reconciliation; it does not mean
remote replication was uncertain (`../../terrabase/crates/tb-server/src/document_service.rs:196-223,412-465`,
`../../terrabase/crates/tb-server/src/local_v1_runtime.rs:1140-1180`,
`../../terrabase/crates/tb-server/tests/distributed_client_process.rs:55-85`,
`../../terrabase/crates/tb-server/tests/client_process.rs:55-90`).

Rust authority opening installs a certificate in a fresh shard directory or
reopens the exact accepted record. It does not implement a predecessor-linked
successor transition (`../../terrabase/crates/tb-replication/src/authority.rs:1033-1180`).

The real Go controller caller starts `placement.StartController` with its
JetStream placement store, OCI fleet, host controller, and admitted artifact
resolver (`internal/app/controller.go:190-255`). The reconciler admits one
active region with two fixed member seats; it holds while awaiting independent
serving evidence, moves an observed `StageServing` member back to
`StageAwaitingRuntimeContract`, and holds all retirement stages until an
integrated evidence-driven scale-in path exists (`internal/placement/controller.go:197-204,280-297,580-610`).
The two-survivor, distinct-failure-domain check in the placement helpers is a
topology floor, not a TerraBase write-quorum rule
(`internal/placement/terrabase.go:969-1035`).

Go's host status decoder accepts schema 1 only and rejects `serving=true` or
either capability bit being true. The managed host reporter binds the report
to the exact managed member, volume, mount, and native process, and reports
storage recovery and replication-listener readiness; it does not report
per-origin durable/applied frontiers or a drain receipt
(`internal/host/member_status.go:365-391`,
`internal/host/managed_runtime.go:715-752`). Go placement intent is schema 5:
each active region produces two seats, and supersession preserves continuing
rows and the authority reference (`internal/placement/terrabase.go:18-25,405-452`).
Schema-5 supersession currently rejects seat removal unconditionally; separate
`CanRetire` and `CanBeginRetirement` helpers test topology and evidence
predicates but are not integrated into the controller retirement path. These
are current holds and validation seams, not an implemented distributed-serving
lifecycle.

## Proposed distributed-serving contract

### Commit acknowledgement

For each accepted transaction, the document owner first commits the
transaction and event to its local WAL. Client success then requires fresh,
authenticated durable acknowledgements from the write quorum selected by the
installed signed authority. Every acknowledgement must bind the exact
database, shard, event origin member ID and incarnation, event sequence,
authority epoch/configuration, and acknowledging member. A frontier above the
sender's audited local source high-water is invalid.

With today's two-member sender profile, one remote durable acknowledgement
means both members have the transaction durably stored. For any larger roster,
the signed policy must define an intersecting write quorum and its failure
assumptions before implementation; the current certificate parser's member
count bound does not provide that policy. `AppliedAck` remains a separate
frontier for read visibility. It must not be substituted for durable
acknowledgement or silently conflated with it.

If the local commit is durable but the required remote acknowledgement is
missing, stale, or unknown, return an explicit uncertain outcome such as
`commit_uncertain`, together with the stable transaction ID. A retry with that
ID must reconcile the original transaction and its required remote receipts;
it must not create a second event or report success from a transient lag gauge.
Persist enough evidence, or provide an authenticated restart-recoverable
frontier query, to reproduce the result after a connection or process restart.

Keep local-v1 semantics separately named in the implementation. Greenfield
scope permits a new client contract; it does not make the existing
`local_durable` receipt evidence of distributed durability.

### Serving and durable drain evidence

Serving proof must be fresh and identity-bound to the exact member incarnation,
authority, process, managed volume/mount, and a selected set of survivor
frontiers. For each named survivor, expose its failure domain plus durable and
applied frontier for the exact departing origin and authority. Bind the proof
to a fresh challenge or an equivalent replay-verifiable receipt. Local
`ready`, authenticated status, an active process, or a zero-lag observation
alone never authorizes service or retirement.

A drain command carries a stable command ID and placement/member generation.
The Rust document owner closes write admission and persists the accepted-write
cutoff through the same serialized path that admits commits. It resolves
in-flight and uncertain transactions through that cutoff, then recovers with
the member still fenced after restart. The idempotent drain receipt records
the exact member and incarnation, command/generation, old authority,
accepted-write cutoff, and each named survivor's identity, failure domain,
durable frontier, and applied frontier. Retirement remains held until every
required survivor has durably received and applied through the cutoff and all
proof fields match current authority. A duplicate command returns the same
receipt; a conflicting command ID, stale generation, missing frontier, or
frontier below the cutoff is rejected.

The exact receipt wire schema, freshness window, and quorum/failure policy are
not present in the current source. Freeze and review them before exposing a
serving-proof or drain endpoint.

## Proposed lifecycle and ordering

1. **Admit a versioned placement and authority.** Establish a signed roster
   with at least three members in the retirement domain, distinct failure
   domains, explicit member incarnations, and a reviewed quorum policy. The
   current two-seat placement profile cannot lose one seat and retain its
   two-survivor floor. A three-member certificate count alone is insufficient:
   sender quorum, survivor rules, Go placement rows, and authority validation
   must all support the same roster.
2. **Admit writes under one authority.** Persist the local event and
   transaction identity, gather the required certified durable acknowledgments,
   then return the distributed success receipt. Report application progress
   separately. Reconcile uncertain commits by the same transaction ID.
3. **Fence the retiring writer.** Persist the idempotent drain command and
   close admission atomically with an accepted-write cutoff. Drain every
   accepted in-flight write; no post-cutoff write may receive success under
   the old generation. A crash or loss of quorum leaves the member fenced and
   the operation held.
4. **Prove survivor frontiers.** Freshly query or verify restart-recoverable
   receipts from the named survivors. Require their durable and applied
   frontiers to cover the cutoff and bind each to origin incarnation,
   authority, configuration, nonce/freshness, and failure domain. Persist the
   resulting drain receipt before advancing placement state.
5. **Install a predecessor-linked successor authority.** The signed successor
   names the predecessor certificate digest, a strictly increasing epoch,
   the continuing and replacement incarnations, and the old-origin cutoff.
   Retain the predecessor certificate for replay verification. Fence old
   writes, publish the ordered successor, and durably install it on the
   required survivors before enabling successor writes. If the old process is
   partitioned and cannot be proven fenced, fail closed unless an independently
   verified compute or storage fence makes old writes impossible. A Go lease or
   expired host session alone is not that proof.
6. **Commit placement retirement by CAS.** Extend the placement schema and
   supersession checks to carry the exact drain receipt and successor authority
   reference. Apply a compare-and-swap transition only after the native receipt
   and successor-install evidence are verified. Then stop/unmount the exact
   process, verify writer-stop and attachment state, detach the retained
   volume, and only later terminate the exact OCI instance. Missing or stale
   evidence leaves placement and resources held.

The source does not define one ordered transaction spanning Rust's accepted
authority record and Go's JetStream placement intent. Before implementation,
choose and test how the authority publisher orders the signed successor and
the placement-generation update, including crash recovery between them. Do
not assume the two existing stores commit atomically.

## Ownership seams

| Owner | Proposed responsibility | Current seam |
| --- | --- | --- |
| Rust document owner | Serialize write admission with the durable cutoff; make client success depend on required remote durable receipts; persist idempotent drain state and cutoff; report durable separately from applied. | `tb-server/src/document_service.rs`, `tb-server/src/replication_sender.rs`, `tb-document/src/distributed_apply.rs` |
| Rust replication receiver and journal | Authenticate the peer/event; durably record contiguous per-origin progress; recover and expose nonce-bound durable/applied frontiers; reject stale or cross-authority receipts. | `tb-server/src/replication_server.rs`, `tb-replication/src/journal.rs` |
| Rust authority consumer | Validate predecessor/successor chain and monotonic epoch; durably install and recover the exact accepted successor before writes reopen. | `tb-replication/src/authority.rs` |
| Authority publisher | Own signer authorization and serialized publication of the successor certificate and transition record; preserve predecessor/cutoff evidence for replay. | No current producer/ordered transition caller is established by the reviewed runtime path; ownership and its durable log integration must be assigned before coding. |
| Go managed host | Authenticate the exact native process/session and mount/volume; relay its fresh, bounded proof and durable drain receipt without inferring database durability from process or mount state. | `internal/host/member_status.go`, `internal/host/managed_runtime.go`, `internal/app/controller.go` |
| Go placement | Persist the versioned roster and member-generation transition by CAS; verify the native receipt and successor reference; hold OCI scale-in until writer-stop, detach, and retention checks pass. | `internal/placement/controller.go`, `internal/placement/terrabase.go`, `internal/placement/store.go` |

## Required implementation tests

| Test cut | Required evidence |
| --- | --- |
| Client write and retry | Exact 2-of-2 durable receipt gates success; lost/stale acknowledgement after local commit returns uncertainty with the same transaction ID; retry returns the original event and receipt. |
| Durable versus applied | Delay D5 apply after durable receive: durable acknowledgement may advance, applied does not; reads and drain remain blocked until their own applied-frontier requirement is met. |
| Recovery boundaries | Crash after local WAL commit, peer append, durable marker sync, ACK send, cutoff persistence, drain-receipt persistence, successor publication, and successor installation. Restart must recover the same transaction/cutoff and must not reopen a fenced writer. |
| Identity and frontier rejection | Reject wrong peer, origin/incarnation, epoch, configuration, nonce, event, failure domain, stale receipt, duplicate conflict, and any durable/applied frontier above the sender high-water or below the cutoff. Test an explicit zero frontier; do not infer health from zero lag. |
| Drain idempotency | Repeating the same command ID/generation returns the same receipt after restart; changed command scope or generation conflicts; unknown outcome holds for exact reconciliation. |
| Authority succession | Prove predecessor digest and increasing epoch, continuing/replacement identity, old cutoff, retained old-certificate replay, and durable install on every required survivor. Partition the old member and prove no two authorities can acknowledge writes; otherwise require external fencing or remain held. |
| Placement CAS and caller | Exercise the actual `internal/app` placement caller with signed native proofs; reject stale/mismatched evidence and CAS conflicts; prove the authority and intent ordering across each crash boundary; OCI detach/termination never precedes native drain and writer-stop proof. |
| Roster and failure domains | Exercise a real three-or-more-member roster and the chosen intersecting quorum under node loss, partition, replacement, and recovery. Show two survivors remain in distinct failure domains before retirement. |

Unit fixtures that set `ReplicationHealthy`, `QuorumSafe`, or `WriterStopProof`
to arbitrary values are necessary predicate tests, not evidence that Rust,
host, placement, and OCI callers exchange the required proof. End-to-end
cross-language tests must consume actual authenticated receipts.

## Current two-VM proof boundary

The managed-member Firecracker lane describes two guests with separate ext4
volumes, the real Go host controller and native process runner, and a pinned
TerraBase binary. Its driver checks a fixture-unique write on A and read on B,
including B's pre-write absence and post-write value, B's durable/applied ACK
counters, and A's sender lag gauge (`tests/firecracker/managedmember/README.md`,
`internal/host/managed_member_firecracker_test.go`). Its controller uses a
test-only registration verifier.

That bounded data-path check does not implement or qualify the serving-proof,
drain, durable cutoff, survivor-set, successor-authority, or placement
retirement protocol described here. A zero sender-lag gauge and one applied
test write do not prove durable receipts survive restart, prevent a partitioned
old writer, establish a production quorum, or authorize volume detach. The
harness does not qualify OCI ownership, production enrollment, autoscaling, or
multiple regions. A successful build or fixture check is not a VM run result;
any VM result must be tied to its own immutable input manifest and evidence
receipt.

## Decisions and gates before implementation

- Define the signed write quorum and failure assumptions for three-or-more
  members; reconcile them with the placement two-survivor topology floor.
- Choose whether durable/applied receipts are queried from recovered receiver
  frontiers or persisted at the sender, and specify nonce/freshness and replay
  rules.
- Assign the authority publisher and define crash-safe ordering between the
  Rust successor record and Go placement generation; neither current store
  provides a cross-store transaction.
- Specify independent proof that a partitioned old writer is unable to commit
  before enabling a successor. If no such proof is available, retirement must
  remain held.
- Define the new versioned client result for distributed success and
  `commit_uncertain`; keep local-v1's `local_durable` meaning explicit during
  implementation. No compatibility shim is required by this greenfield plan.
- Extend Go placement intent/member schemas beyond schema 5 with native
  receipt binding, authority succession, and replay-safe CAS/recovery.
- Require a real three-or-more-member fault-injection run before enabling
  automated drain, scale-in, volume detach, or member replacement.

Until these gates and the tests above pass in the real Rust/Go callers, the
only supported claims remain local process/storage readiness and bounded
replication observations. Serving admission and retirement stay unimplemented.
