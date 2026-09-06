# Durable work inventory and delivery policy

> Current implementation inventory for NATS-backed Orchestrator control work.
> Subject tokens name the mandatory `ts.orch.v1` control root selected by the
> workspace `GOAL.md`; the checked-in adapter serves that v1 root. It does not
> define TerraBase durability.
> NATS is the Orchestrator v1 control store: replacing it is a new goal and ADR
> decision, and any replacement must migrate acknowledged control work without
> losing identity, fencing, or receipts.

| | |
| --- | --- |
| Contract version | 1 |
| Ratified by | `TerraScale.Orchestrator` contract review |
| Machine-readable definitions | `src/orchestrator/protocol/durable_work_inventory.go` (typed inventory), `messaging_delivery_semantics.go` (bounded redelivery, duplicate windows, poisoning, queue-group ownership) |
| Drift binding | Go protocol tests pin completeness and policy binding; Go control tests bind the table to the provisioning topologies (`NatsTopology`, `GlobalNatsTopology`) and every consumer name a runtime reconciles |
| Canonicality | `docs/contracts/nats-capability-matrix.md` remains the ONE canonical NATS capability contract; this document is the canonical per-stream, per-consumer inventory beneath it and defers to it on capability dispositions |

Delivery claim: **effectively-once mutation through operation-level idempotency keys and fencing — never exactly-once delivery.** Message-id transport windows (2 min) suppress transport-level replays only; a duplicate outside the window is admitted and the idempotency key decides the effect.

## 1. Durable streams

The table records the ordinary profiles currently declared by
`src/orchestrator/protocol/durable_work_inventory.go`. `Domain` is the existing
profile classification and `R` is its declared replica count; neither proves
that a separate regional cluster is installed or required for every Region.

| Stream | Domain | Subjects | Class | R | Retention | Max age | Max bytes | Discard | Duplicate window | Terminal evidence behavior |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `CELL_SPEC` | RegionalCell | `ts.orch.v1.{cell}.desired.>` | AuthoritativeJournal | 3 | Limits | 30 d | 256 MiB | Old | 2 min | Deterministic conflicts terminate with terminal evidence; exhaustion warns on the final delivery. |
| `CELL_OPERATIONS` | RegionalCell | `ts.orch.v1.{cell}.operation.>` | AuthoritativeJournal | 3 | Limits | 30 d | 1 GiB | Old | 2 min | KV CAS plus operation proofs fence every append. |
| `CELL_EVENTS` | RegionalCell | `ts.orch.v1.{cell}.observation.>` | Replayable | 3 | Limits | 30 d | 256 MiB | Old | 2 min | Consumers reconcile from journals, so loss or replay is safe. |
| `GLOBAL_SPEC` | GlobalControl | `ts.orch.v1.global.desired.>` | AuthoritativeJournal | 3 | Limits | 30 d | 256 MiB | Old | 2 min | Deterministic conflicts terminate with terminal evidence. |

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

The signed pre-customer bootstrap is a separate, bounded R1 projection.
`src/orchestrator/initialcontrol/profile.go` builds GRU regional and global
account inventories on the seed broker, explicitly changes their replica
counts to one, and retains the limits above. It does not change ordinary R3
validation or implement the final multi-Region mapping. See
[initial GRU R1](initial-gru-r1.md), [global storage](global-control-storage.md)
and [snapshot transition](control-snapshot-transition.md) for retained inventory
and the incomplete R1-to-R3 integration. Customers cannot be admitted under R1,
and promotion must never permit a subsequent downgrade.

## 2. Durable consumer profiles

| Consumer | Stream | Filter subject | Ownership | Ack | Max deliver | Backoff | Max pending | Batch / expires / waiting |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `runtime_startup` | `CELL_EVENTS` | `ts.orch.v1.{cell}.observation.runtime.started.>` | RegionalEquivalentWorkers | Explicit | 5 | 1/5/15/30 s | 32 | — / — / 16 |
| `gitops_cell_spec_{instance}` | `CELL_SPEC` | `ts.orch.v1.{cell}.desired.gitops` | RegionalFencedAuthority | Explicit | 5 | 1/5/15/30 s | 8 | 1 / 30 s / 8 |
| `global_cell_spec_{cell}` | `GLOBAL_SPEC` | `ts.orch.v1.global.desired.gitops.{cell}` | GlobalFencedAuthority | Explicit | 5 | 1/5/15/30 s | 8 | 1 / 30 s / 8 |

All profiles are pull consumers bounded by `MaxAckPending`, `MaxBatch`, `MaxExpires`, and `MaxWaiting`; no push delivery shape is adopted. The declared ack wait equals the first backoff interval (JetStream derives it). Exhaustion stops redelivery only with terminal evidence; no message disappears silently. Stateful mutation ownership is fenced: only the live lease holder (epoch plus KV revision, re-checked before the effect and before the acknowledgement) may write an authoritative journal; queue groups never choose an authoritative writer.

## 3. Message-id deduplication layering

- Publishers derive `Nats-Msg-Id` deterministically from the exact content being stored (payload digest, attempt, fencing token, or writer epoch), so a duplicate publish acknowledgement PROVES the identical message is already stored: retries converge (`NatsPublishConvergence.EnsureStored`), they never throw until a window expires.
- Consumers layer a bounded transport window (`NatsMessageIdDeduplication`) beneath the journal's idempotency keys: the window records an identity only after its durable effect is proven, a suppressed replay is acknowledged as a verified idempotent replay, and the same identity with a different digest terminates loudly with terminal evidence instead of being silently swallowed by the server-side window.

## 4. Queue groups (regional work-queue ownership)

| Group | Domain | Distribution rule | Fencing basis |
| --- | --- | --- | --- |
| `orchestrator_{cell}` | RegionalCell | Equivalent-worker regional service endpoints; any member may answer health, status, or members queries. | No authoritative write rides the group; answers are equivalent and cell-scoped subjects keep membership regional. |
| `terrascale_orchestrator_journal_writer_{cell}` | RegionalCell | Equivalent-worker journal writer fan-in for one regional cell only. | Every authoritative append is fenced by the regional lease epoch and single-use operation proofs before and after the write. |

## 5. Evidence

Real-NATS proofs belong in the Go control and delivery integration tests (the
host-agent lane): message-id suppression including the silently-swallowed
conflicting payload, durable replay after consumer recreation converging through
idempotency, lost-acknowledgement redelivery inside the backoff bound, and
redelivery stopping at the declared delivery cap.
