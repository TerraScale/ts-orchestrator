# Durable work inventory and delivery policy

> Current inventory for NATS-backed Orchestrator control work. The subject
> tokens use the mandatory `ts.orch.v2` root. This contract does not define
> TerraBase durability or place NATS on a customer data path.

| | |
| --- | --- |
| Contract version | 2 |
| Machine-readable definitions | `src/orchestrator/protocol/durable_work_inventory.go` (typed inventory), `messaging_delivery_semantics.go` (bounded redelivery, duplicate windows, poisoning, queue-group ownership) |
| Drift binding | Go protocol tests pin every stream, consumer, queue group, and delivery rule |
| Canonicality | `docs/contracts/nats-capability-matrix.md` owns capability dispositions; this file owns the stream and consumer inventory |

Delivery claim: **effectively-once mutation through operation-level idempotency keys and fencing — never exactly-once delivery.** Message-id transport windows (2 min) suppress transport-level replays only; a duplicate outside the window is admitted and the idempotency key decides the effect.

## 1. Durable streams

| Stream | Domain | Subjects | Class | R | Retention | Max age | Max bytes | Discard | Duplicate window | Terminal record behavior |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `CELL_SPEC` | RegionalCell | `ts.orch.v2.{cell}.desired.>` | AuthoritativeJournal | 3 | Limits | 30 d | 256 MiB | Old | 2 min | Deterministic conflicts write a terminal record; exhaustion warns on the final delivery. |
| `CELL_OPERATIONS` | RegionalCell | `ts.orch.v2.{cell}.operation.>` | AuthoritativeJournal | 3 | Limits | 30 d | 1 GiB | Old | 2 min | KV CAS plus operation proofs fence every append. |
| `CELL_EVENTS` | RegionalCell | `ts.orch.v2.{cell}.event.>` | Replayable | 3 | Limits | 30 d | 256 MiB | Old | 2 min | Consumers reconcile from journals, so loss or replay is safe. |
| `GLOBAL_SPEC` | GlobalControl | `ts.orch.v2.global.desired.>` | AuthoritativeJournal | 3 | Limits | 30 d | 256 MiB | Old | 2 min | Deterministic conflicts write a terminal record. |
| `GLOBAL_CI` | GlobalControl | `ts.orch.v2.global.ci.>` | WorkQueue | 3 | Limits | 30 d | 1 GiB | Old | 24 h | Trigger conflicts and runner identity conflicts terminate loudly; exhaustion warns on the final delivery. |

### Required placement and current implementation

[GOAL.md](../../../GOAL.md#ts-orchestrator) governs physical storage placement. Production has one
permanent global R3, with one selected replica co-hosted in each of GRU, SFO
and FRA. Every Region starts with two member hosts, each running its own local
orchestrator. Regional controllers use the global R3 for authoritative control
records; adding a controller or Region does not add a storage replica or grant
global authority. A later independent regional R3 requires at least three
eligible hosts and a separate declaration. It remains post-launch work.

Cell-scoped subjects and fenced regional ownership remain required regardless
of where the records are stored. The permanent global R3 crosses the three
launch Regions. Existing gateway restrictions do not prohibit that required
storage topology and do not establish its implementation.

The code still declares `RegionalCell` as a regional JetStream domain and
constructs separate regional and global profiles through `NatsTopology` and
`GlobalNatsTopology`. The complete mapping of each Region's streams, buckets,
consumers and permissions onto the shared global R3 is not yet wired and
qualified. In particular, the fixed `CELL_*` names are not evidence that
multiple Region inventories can coexist in one account. Production composition
must define the actual isolation, naming and credential mapping and prove
regional lease and receipt access through it. Update the typed inventory,
provisioners, runtime readers and tests together when that mapping is admitted.
Do not deploy independent R3 groups merely to satisfy the existing profiles.

The signed pre-customer bootstrap is a separate, bounded R1 projection. The
retired Go `initialcontrol` implementation is historical; the active C# source
map is [DESIGN.md](../../DESIGN.md), and the current topology declarations are
in `src/TerraScale.Orchestrator/Messaging/NatsTopology.cs` and
`GlobalNatsTopology.cs`. The R1 projection does not change ordinary R3
validation or implement the final multi-Region mapping. See
[initial GRU R1](initial-gru-r1.md), [global storage](global-control-storage.md)
and [snapshot transition](control-snapshot-transition.md) for retained inventory
and the incomplete R1-to-R3 integration. Customers cannot be admitted under R1,
and promotion must never permit a subsequent downgrade.

## 2. Durable consumer profiles

| Consumer | Stream | Filter subject | Ownership | Ack | Max deliver | Backoff | Max pending | Batch / expires / waiting |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `runtime_startup` | `CELL_EVENTS` | `ts.orch.v2.{cell}.observation.runtime.started.>` | RegionalEquivalentWorkers | Explicit | 5 | 1/5/15/30 s | 32 | — / — / 16 |
| `gitops_cell_spec_{instance}` | `CELL_SPEC` | `ts.orch.v2.{cell}.desired.gitops` | RegionalFencedAuthority | Explicit | 5 | 1/5/15/30 s | 8 | 1 / 30 s / 8 |
| `gitops_global_cell_spec_{cell}` | `GLOBAL_SPEC` | `ts.orch.v2.global.desired.gitops.{cell}` | GlobalFencedAuthority | Explicit | 5 | 1/5/15/30 s | 8 | 1 / 30 s / 8 |
| `global_ci_trigger` | `GLOBAL_CI` | `ts.orch.v2.global.release.ci.forgejo` | GlobalFencedAuthority | Explicit | 5 | 1/5/15/30 s | 32 | — / — / 16 |
| `global_ci_runtime_proof` | `GLOBAL_CI` | `ts.orch.v2.global.release.ci.runtime-proof` | GlobalFencedAuthority | Explicit | 5 | 1/5/15/30 s | 32 | 1 / 30 s / 16 |
| `ci_runner_{zone}_{runner}` | `GLOBAL_CI` | `ts.orch.v2.global.release.ci.job.{zone}.{runner}` | ReconciledRunnerIdentity | Explicit | 5 | 1/5/15/30 s | 1 | 1 / 30 s / 4 |

All profiles are pull consumers bounded by `MaxAckPending`, `MaxBatch`, `MaxExpires`, and `MaxWaiting`; no push delivery shape is adopted. The declared ack wait equals the first backoff interval (JetStream derives it). Exhaustion stops redelivery only after a terminal record; no message disappears silently. Stateful mutation ownership is fenced: only the live lease holder (epoch plus KV revision, re-checked before the effect and before the acknowledgement) may write an authoritative journal; queue groups never choose an authoritative writer.

## 3. Message-id deduplication layering

- Publishers derive `Nats-Msg-Id` deterministically from the exact content being stored (payload digest, attempt, fencing token, or writer epoch), so a duplicate publish acknowledgement PROVES the identical message is already stored: retries converge (`NatsPublishConvergence.EnsureStored`), they never throw until a window expires.
- Consumers layer a bounded transport window (`NatsMessageIdDeduplication`) beneath the journal's idempotency keys: the window records an identity only after its durable effect is proven, a suppressed replay is acknowledged as a verified idempotent replay, and the same identity with a different digest writes a terminal conflict record instead of being silently swallowed by the server-side window.

## 4. Queue groups (regional work-queue ownership)

| Group | Domain | Distribution rule | Fencing basis |
| --- | --- | --- | --- |
| `orchestrator_{cell}` | RegionalCell | Equivalent-worker regional service endpoints; any member may answer health, status, or members queries. | No authoritative write rides the group; answers are equivalent and cell-scoped subjects keep membership regional. |
| `terrascale_orchestrator_journal_writer_{cell}` | RegionalCell | Equivalent-worker journal writer fan-in for one regional cell only. | Every authoritative append is fenced by the regional lease epoch and single-use operation proofs before and after the write. |

## 5. Verification

Go control and delivery integration tests cover message-ID suppression,
conflicting payloads, durable replay after consumer recreation, idempotent
convergence, lost-acknowledgement redelivery inside the backoff bound, and
redelivery stopping at the declared cap.
