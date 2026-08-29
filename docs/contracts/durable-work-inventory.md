# Durable work inventory and delivery policy

> Current implementation inventory for NATS-backed Orchestrator control work.
> It does not define TerraBase durability and does not make NATS a permanent
> control-plane dependency. Replacement must migrate acknowledged control work
> without losing identity, fencing, or receipts.

| | |
| --- | --- |
| Contract version | 1 |
| Ratified by | `TerraScale.Orchestrator` issue #22 (parent #16, dependencies #17, #18, #20) |
| Machine-readable definitions | `src/TerraScale.Orchestrator/Protocol/Messaging/DurableWorkInventory.cs` (typed inventory), `MessagingDeliverySemantics.cs` (bounded redelivery, duplicate windows, poisoning, queue-group ownership) |
| Drift binding | `tests/TerraScale.Orchestrator.Protocol.Tests/DurableWorkInventoryTests.cs` pins completeness and policy binding; `tests/TerraScale.Orchestrator.Tests/DurableWorkInventoryDriftTests.cs` binds the table to the provisioning topologies (`NatsTopology`, `GlobalNatsTopology`) and to every consumer name a runtime reconciles |
| Canonicality | `docs/contracts/nats-capability-matrix.md` remains the ONE canonical NATS capability contract; this document is the canonical per-stream, per-consumer inventory beneath it and defers to it on capability dispositions |

Delivery claim: **effectively-once mutation through operation-level idempotency keys and fencing — never exactly-once delivery.** Message-id transport windows (2 min regional, 24 h global CI) suppress transport-level replays only; a duplicate outside the window is admitted and the idempotency key decides the effect.

## 1. Durable streams

| Stream | Domain | Subjects | Class | R | Retention | Max age | Max bytes | Discard | Duplicate window | Terminal evidence behavior |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `CELL_SPEC` | RegionalCell | `ts.orch.v1.{cell}.desired.>` | AuthoritativeJournal | 3 | Limits | 30 d | 256 MiB | Old | 2 min | Deterministic conflicts terminate with terminal evidence; exhaustion warns on the final delivery. |
| `CELL_OPERATIONS` | RegionalCell | `ts.orch.v1.{cell}.operation.>` | AuthoritativeJournal | 3 | Limits | 30 d | 1 GiB | Old | 2 min | KV CAS plus operation proofs fence every append. |
| `CELL_EVENTS` | RegionalCell | `ts.orch.v1.{cell}.event.>` | Replayable | 3 | Limits | 30 d | 256 MiB | Old | 2 min | Consumers reconcile from journals, so loss or replay is safe. |
| `GLOBAL_SPEC` | GlobalControl | `ts.orch.v1.global.desired.>` | AuthoritativeJournal | 3 | Limits | 30 d | 256 MiB | Old | 2 min | Deterministic conflicts terminate with terminal evidence. |
| `GLOBAL_CI` | GlobalControl | `ts.orch.v1.global.ci.>` | WorkQueue | 3 | Limits | 30 d | 1 GiB | Old | 24 h | Trigger conflicts and runner identity conflicts terminate loudly; exhaustion warns on the final delivery. |

Regional rows are per-cell: each region owns its streams inside its own JetStream domain, and no stream or durable consumer spans regions (gateway plan admission rejects WAN-spanning assets).

## 2. Durable consumer profiles

| Consumer | Stream | Filter subject | Ownership | Ack | Max deliver | Backoff | Max pending | Batch / expires / waiting |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `runtime_startup` | `CELL_EVENTS` | `ts.orch.v1.{cell}.event.runtime.started.>` | RegionalEquivalentWorkers | Explicit | 5 | 1/5/15/30 s | 32 | — / — / 16 |
| `gitops_cell_spec_{instance}` | `CELL_SPEC` | `ts.orch.v1.{cell}.desired.gitops` | RegionalFencedAuthority | Explicit | 5 | 1/5/15/30 s | 8 | 1 / 30 s / 8 |
| `gitops_global_cell_spec_{cell}` | `GLOBAL_SPEC` | `ts.orch.v1.global.desired.gitops.{cell}` | GlobalFencedAuthority | Explicit | 5 | 1/5/15/30 s | 8 | 1 / 30 s / 8 |
| `global_ci_trigger` | `GLOBAL_CI` | `ts.orch.v1.global.ci.forgejo` | GlobalFencedAuthority | Explicit | 5 | 1/5/15/30 s | 32 | — / — / 16 |
| `global_ci_runtime_proof` | `GLOBAL_CI` | `ts.orch.v1.global.ci.runtime-proof` | GlobalFencedAuthority | Explicit | 5 | 1/5/15/30 s | 32 | 1 / 30 s / 16 |
| `ci_runner_{zone}_{runner}` | `GLOBAL_CI` | `ts.orch.v1.global.ci.job.{zone}.{runner}` | ReconciledRunnerIdentity | Explicit | 5 | 1/5/15/30 s | 1 | 1 / 30 s / 4 |

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

Real-NATS proofs live in `tests/TerraScale.Orchestrator.Tests/NatsDurableDeliveryTests.cs` (rootless Podman lane): message-id suppression including the silently-swallowed conflicting payload, durable replay after consumer recreation converging through idempotency, lost-acknowledgement redelivery inside the backoff bound, and redelivery stopping at the declared delivery cap.
