# Stable contract fixture for isolated model-test runs.

Last revised: 2026-08-29.

### Requirements

| ID | Requirement |
| --- | --- |
| `REQ-ORCH-001` | GRU runs the permanent global authority. |
| `REQ-ORCH-002` | Every global and regional controller group has three replicas and one active leader. |
| `REQ-ORCH-003` | Every NATS control domain uses JetStream file storage with three replicas. |
| `REQ-ORCH-004` | Every active Region operates safely during GRU or WAN loss from its last accepted policy. |
| `REQ-ORCH-005` | GRU receives the complete regional journal after connectivity returns. |
| `REQ-ORCH-006` | The Orchestrator bootstraps and owns the greenfield OCI estate without Pulumi or OpenTofu. |
| `REQ-ORCH-007` | OCI mutations use typed, region-scoped provider actuators and durable journals. |
| `REQ-ORCH-008` | The scheduler places only admitted immutable workloads on eligible hosts. |
| `REQ-ORCH-009` | TerraBase placement follows database-selected Regions and RF=2 active Members per Region and Partition. |
| `REQ-ORCH-010` | Dashboard and Database API run at least two instances per qualified Region. |
| `REQ-ORCH-011` | Orchestrator provisions workload identity, trust bundles, rotation, and bootstrap grants. |
| `REQ-ORCH-012` | Orchestrator operates Cloudflare global and strict regional routing for no more than twenty active Regions. |
| `REQ-ORCH-013` | Delivery admits exact artifacts, provenance, configuration, migrations, and rollback anchors. |
| `REQ-ORCH-014` | Autoscaling uses sustained typed capacity reports and preserves hard safety ceilings. |
| `REQ-ORCH-015` | Every long-running action exposes durable exact progress and a terminal receipt. |
| `REQ-ORCH-016` | Regional and global control state has backup, restore, corruption, and total-rebuild evidence. |
| `REQ-ORCH-017` | Operators receive typed plans, holds, approvals, progress, and redacted evidence. |
| `REQ-ORCH-018` | The production release qualifies GRU, SFO, FRA, ARM64 control hosts, ARM64 and x86_64 TerraBase workload hosts, OCI, NATS, systemd, containerd, Block Volume, Vault, Object Storage, and Cloudflare. |
| `REQ-ORCH-019` | The architecture supports a deterministic twenty-Region simulation before the fourth Region is published. |
| `REQ-ORCH-020` | No customer-serving request requires a live Orchestrator or NATS lookup. |
| `REQ-ORCH-021` | The production repository, solution, runtime, and artifact contain no embedded development-host composition or DevHost dependency. |
| `REQ-ORCH-022` | Every production upgrade creates and qualifies a parallel regional candidate before cutover. |
| `REQ-ORCH-023` | Every host publishes admitted capacity, reserved capacity, allocatable capacity, pressure, shutdown, and reclamation state. |
| `REQ-ORCH-024` | Every workload uses a closed execution mode, restart policy, priority class, preemption policy, network lease, and filesystem-reclamation contract. |
| `REQ-ORCH-025` | Resource status, list, and watch APIs expose conditions, `observedGeneration`, stable pagination, resumable progress, compaction recovery, and bounded overload behavior. |
| `REQ-ORCH-026` | Dependency-aware deletion uses durable typed blockers and verified absence before final removal. |
| `REQ-ORCH-027` | Reconcile, reconnect, health, and provider work queues are bounded, fair, coalesced by resource, and safe under retry storms. |
| `REQ-ORCH-028` | Rebalancing and consolidation preserve disruption budgets, failure headroom, surge capacity, storage safety, and a measured net benefit. |

### Invariants

| ID | Invariant |
| --- | --- |
| `INV-ORCH-001` | One exact authority term may mutate one control scope. |
| `INV-ORCH-002` | Global policy has one writer in GRU. |
| `INV-ORCH-003` | Regional mutation requires the current local term and local NATS quorum. |
| `INV-ORCH-004` | An isolated Region cannot create a new global generation. |
| `INV-ORCH-005` | Desired state never erases a provider or TerraBase observation. |
| `INV-ORCH-006` | Every external mutation is preceded by durable authorized intent. |
| `INV-ORCH-007` | Unknown provider outcome is reconciled before retry or compensation. |
| `INV-ORCH-008` | One provider resource has one active lifecycle owner. |
| `INV-ORCH-009` | Tags and discovery never grant mutation authority. |
| `INV-ORCH-010` | A stale leader cannot complete a new accepted mutation. |
| `INV-ORCH-011` | A committed provider target remains fixed across leadership change. |
| `INV-ORCH-012` | NATS never carries customer data or TerraBase correctness state. |
| `INV-ORCH-013` | TerraBase alone accepts membership and retirement. |
| `INV-ORCH-014` | Scale-in cannot reduce required durability or recovery headroom. |
| `INV-ORCH-015` | Secrets and private keys never enter desired state, NATS, telemetry, receipts, or Git. |
| `INV-ORCH-016` | A release activates only the exact qualified digest and configuration. |
| `INV-ORCH-017` | Catalog discovery and catalog publication are separate transitions. |
| `INV-ORCH-018` | A retired `RegionCode`, Member identity, replica epoch, volume identity, or bootstrap generation is never reused unsafely. |
| `INV-ORCH-019` | Admission and backpressure protect workloads before capacity arrives. |
| `INV-ORCH-020` | Telemetry cannot authorize a destructive operation. |
| `INV-ORCH-021` | An active allocation is never mutated in place during release. |
| `INV-ORCH-022` | Development composition, credentials, trust roots, and authority paths cannot enter a production artifact or state store. |
| `INV-ORCH-023` | Production traffic cannot reach a candidate before its exact generation satisfies minimum healthy time and every required gate. |
| `INV-ORCH-024` | One active allocation owns one unique, durable IP and port lease for each bound endpoint. |
| `INV-ORCH-025` | A resource cannot disappear while a current typed deletion blocker, live dependent, or unverified external resource remains. |
| `INV-ORCH-026` | Status cannot claim a desired generation applied until `observedGeneration` equals that generation. |
| `INV-ORCH-027` | Host pressure stops new placement before eviction, and planned shutdown drains admitted work before poweroff. |
| `INV-ORCH-028` | Queue overload sheds, delays, or coalesces work without dropping durable intent or creating unbounded memory use. |

### Security rules

| ID | Rule |
| --- | --- |
| `SEC-ORCH-001` | Every privileged network boundary uses TLS 1.3 and mutual workload identity. |
| `SEC-ORCH-002` | NATS servers use mTLS; clients also use scoped NKey and JWT identities. |
| `SEC-ORCH-003` | Global, regional, host-agent, CI, monitoring, and infrastructure identities have disjoint permissions. |
| `SEC-ORCH-004` | Regional OCI credentials cannot mutate another Region or the tenancy root. |
| `SEC-ORCH-005` | GRU global controllers do not hold ordinary regional OCI mutation credentials. |
| `SEC-ORCH-006` | Secret configuration contains references and version identities only. |
| `SEC-ORCH-007` | Private keys are non-exportable where OCI Vault supports the required operation. |
| `SEC-ORCH-008` | Bootstrap credentials expire or are revoked after handoff. |
| `SEC-ORCH-009` | Artifacts require immutable digest, signature, provenance, SBOM, and vulnerability disposition. |
| `SEC-ORCH-010` | No ordinary operation requires inbound SSH. |
| `SEC-ORCH-011` | Break-glass access is time-bound, approved, recorded, and automatically revoked. |
| `SEC-ORCH-012` | Logs, traces, metrics, errors, fixtures, and receipts redact secret and customer content before emission. |
| `SEC-ORCH-013` | Development trust roots, certificates, credentials, tokens, and secret defaults never enter production state, images, packages, or deployments. |
| `SEC-ORCH-014` | A workload receives network, port, filesystem, device, secret, and peer access only through its admitted allocation contract. |

### State machines

| ID | State machine |
| --- | --- |
| `SM-ORCH-BOOTSTRAP` | Empty tenancy to accepted GRU authority |
| `SM-ORCH-GLOBAL-AUTHORITY` | Global leader election, renewal, fencing, and replacement |
| `SM-ORCH-REGIONAL-AUTHORITY` | Regional leader election, renewal, fencing, and replacement |
| `SM-ORCH-REGION-ADMISSION` | Planned Region to owner-approved catalog publication |
| `SM-ORCH-REGION-REMOVAL` | Routing fence through final retention and deletion receipts |
| `SM-ORCH-PROVIDER-OPERATION` | Prepared intent through exact provider terminal outcome |
| `SM-ORCH-HOST-LIFECYCLE` | Host request, creation, enrollment, admission, drain, and retirement |
| `SM-ORCH-WORKLOAD-LIFECYCLE` | Artifact admission through allocation, minimum health, service, drain, and verified stop |
| `SM-ORCH-MEMBER-ADD` | TerraBase identity allocation through membership acceptance |
| `SM-ORCH-MEMBER-REPLACE` | Failed seat through verified replacement and safe retirement |
| `SM-ORCH-CAPACITY` | Pressure observation through scale, rebalance, or admission refusal |
| `SM-ORCH-RELEASE` | Immutable blue through parallel green creation, qualification, atomic cutover, rollback window, and blue retirement |
| `SM-ORCH-RECONNECT` | Regional isolation through journal upload and reconciled generation |
| `SM-ORCH-TRUST-ROTATION` | New trust generation through overlap and old-generation retirement |
| `SM-ORCH-CONTROL-RESTORE` | Backup selection through new fenced recovery generation |
| `SM-ORCH-NODE-PRESSURE` | Pressure detection through cordon, reclaim, drain, recovery, or failed-host replacement |
| `SM-ORCH-WORKLOAD-RESTART` | Failure through bounded backoff, stable recovery, rollback, or digest quarantine |
| `SM-ORCH-RESOURCE-DELETION` | Deletion request through dependent drain, blocker release, external absence, and tombstone retention |

### Stable errors

| ID | Meaning |
| --- | --- |
| `ERR-ORCH-AUTHORITY-UNAVAILABLE` | The required authority quorum or current term is unavailable. |
| `ERR-ORCH-STALE-TERM` | A command, executor, or observation belongs to an older authority term. |
| `ERR-ORCH-GENERATION-CONFLICT` | Desired, applied, or observed generations cannot be reconciled automatically. |
| `ERR-ORCH-REGION-ISOLATED` | The requested action is outside the Region's admitted survival policy. |
| `ERR-ORCH-OUTCOME-UNKNOWN` | An external mutation may have occurred and needs observation. |
| `ERR-ORCH-OWNERSHIP-MISMATCH` | Positive resource ownership does not match the requested operation. |
| `ERR-ORCH-EVIDENCE-INCOMPLETE` | Required current and complete evidence is missing. |
| `ERR-ORCH-CAPACITY-UNAVAILABLE` | No eligible placement satisfies resources and safety reserves. |
| `ERR-ORCH-BUDGET-APPROVAL-REQUIRED` | A safe operation exceeds the automatic budget but not the hard ceiling. |
| `ERR-ORCH-PROVIDER-LIMIT` | A provider quota, capacity, or account ceiling blocks the action. |
| `ERR-ORCH-TERRABASE-HOLD` | TerraBase has not accepted the required membership, frontier, or retirement state. |
| `ERR-ORCH-ARTIFACT-DENIED` | Artifact identity, signature, provenance, architecture, or rollback evidence failed. |
| `ERR-ORCH-REGION-NOT-QUALIFIED` | A Region cannot receive customer traffic or placement. |
| `ERR-ORCH-RESTORE-GENERATION-CONFLICT` | A restore might overlap a live control generation. |
| `ERR-ORCH-CANDIDATE-NOT-READY` | The exact candidate has not passed minimum health, compatibility, routing, or required tests. |
| `ERR-ORCH-WORKLOAD-QUARANTINED` | The artifact and configuration pair exceeded its restart or health-failure budget. |
| `ERR-ORCH-DELETION-BLOCKED` | A current dependent, safety hold, or external resource prevents deletion. |
| `ERR-ORCH-WATCH-EXPIRED` | The resume point is below retained journal history and the client must relist. |
