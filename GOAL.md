# TerraScale Orchestrator production goal

Status: owner-directed target architecture and release contract.

Owner: TerraScale workspace owner.

Repository: `TerraScale.Orchestrator/`

Last revised: 2026-08-29.

## Authority

The workspace [`GOAL.md`](../GOAL.md) controls cross-repository product and
TerraBase decisions. This file is the single current goal for the Orchestrator
repository. It defines control authority, regional autonomy, NATS, OCI
provisioning, workload scheduling, identity, delivery, operations, and release
qualification.

This file refines the workspace goal and cannot weaken it. The workspace goal
wins if the two conflict. Within this repository, this file wins over
`docs/architecture/orchestrator.md`, historical specifications, delivery
records, proposed ADRs, tickets, and implementation residue.

The following Orchestrator ADRs remain normative where they agree with this
goal:

| Record | Current use |
| --- | --- |
| [`0033`](docs/adr/0033-gru-global-authority-and-regional-autonomy.md) | GRU global authority, regional autonomy, NATS consensus, state ownership, bootstrap, and reconnect behavior |
| [`0020`](docs/adr/0020-provider-actuator-threat-model.md) | Crash-stop provider mutation fencing and same-operation recovery |
| [`0024`](docs/adr/0024-greenfield-bringup.md) | Greenfield deployment, unknown-resource quarantine, and no historical adoption |
| [`0025`](docs/adr/0025-rollback-on-customer-gate-failure.md) | Rollback on health, security, isolation, replication, billing, or customer-journey failure |
| [`0029`](docs/adr/0029-offer-stateless-tenant-compute.md) | Stateless tenant compute and managed TerraBase as the stateful product |
| [`0031`](docs/adr/0031-run-tenant-workloads-as-unprivileged-oci-containers.md) | Unprivileged OCI containers as the tenant runtime |

ADR 0004 is superseded where it assigns foundation ownership to Pulumi. ADR
0013 remains useful for immutable delivery, dependency ordering, and rollback,
but NATS rather than Git is authoritative after GRU admission. ADR 0018 and ADR
0032 remain superseded. ADR 0026's all-Region activation barrier is superseded.
Its safety intent remains mandatory inside each Region: the active allocation
stays unchanged while a parallel candidate is qualified, and traffic moves
only through a durable regional routing generation. TerraBase uses surge
Members rather than a second independent database cluster.

Implementation status stays honest. A decision here is not proof that code,
cloud resources, performance, security, or recovery work. The repository may
say `implemented` only when code and focused tests exist. It may say
`qualified` only when the required exact-candidate evidence passes. It may say
`production-ready` only after every GA gate in this file passes.

## Owner decisions

The workspace owner selected these contracts during the 2026-08-29 design
interview:

1. GRU owns the permanent global control authority.
2. Every logical Orchestrator group has three replicas and one active leader.
3. JetStream R3 supplies Raft consensus. Orchestrator does not add a second
   application Raft log.
4. GRU runs a global Orchestrator group and a separate ordinary GRU regional
   group.
5. GRU global controllers, GRU regional controllers, and GRU NATS use separate
   production compute.
6. Each non-GRU Region runs three regional controller replicas. Each replica
   shares its host with one regional NATS server under strict resource
   isolation, with NATS receiving the protected priority.
7. Regional Orchestrators continue safe repair, replacement, scaling, storage
   expansion, restart, rollback, and credential renewal when GRU or the WAN is
   unavailable.
8. Isolated Regions cannot create global policy, admit a new artifact, publish
   a Region, widen customer placement, or weaken durability.
9. NATS is the authoritative Orchestrator control store and communication
   network. TerraBase never depends on NATS for data or database correctness.
10. GRU configuration wins desired-state conflicts. Regional committed facts
    and safety operations merge through reconciliation and are never erased to
    make an old plan look successful.
11. The first provider is OCI. Provider-facing contracts remain typed and
    provider-neutral.
12. The first Orchestrator binary creates and records the TerraScale cloud
    estate. Pulumi and OpenTofu are not owners or reconcilers.
13. Production control infrastructure uses ARM64. The scheduler still honors
    the workspace contract for qualified x86 TerraBase Members and artifacts.
14. Customer-visible catalog publication requires explicit owner approval.
15. The architecture supports at most twenty active Regions because the
    initial Cloudflare global load-balancer contract has that ceiling.
16. The production Orchestrator repository, solution, runtime, and artifact
    contain no DevHost project, embedded development lab, `dev` runtime mode,
    local product-host composition, development NATS bootstrap, development
    trust material, or DevHost-specific fixture.
17. Every production workload and control release uses regional blue-green
    deployment. The active version remains unchanged until the exact candidate
    is healthy, works through its real dependencies, and passes its required
    tests.
18. TerraScale adopts proven workload-control mechanics such as pressure
    handling, bounded restart backoff, durable deletion blockers, explicit
    status generations, resumable watches, and disruption budgets through its
    own closed contracts. It does not implement Kubernetes, Nomad, or ECS APIs.

## Mission

Build TerraScale's production control plane. It creates the greenfield OCI
estate, operates one global authority in GRU, runs one autonomous regional
control group per active Region, deploys TerraBaseV2 and the TerraScale product
services, and maintains their capacity, identity, storage, delivery, routing,
and recovery workflows.

The Orchestrator must deploy and operate TerraBaseV2 across a catalog of up to
twenty Regions without becoming a database coordinator. It allocates Member
and volume identities, provisions admitted capacity, starts containers, asks
TerraBase to add or retire seats, and follows TerraBase's accepted membership
and recovery state. It never appoints a database leader, grants a vote, commits
a mutation, merges a CRDT, or declares repair complete without TerraBase
evidence.

The system is production-ready only when it can start from an empty greenfield
tenancy, qualify GRU, SFO, and FRA, survive the required faults, add another
Region, deploy the exact qualified TerraBaseV2 release, autoscale within policy,
restore control and database state, qualify green beside unchanged blue, cut
over through a fenced routing generation, roll back safely, and retain exact
receipts for every claim.

## Product promises

1. One global authority in GRU owns global policy and accepted configuration.
2. Loss of one global or regional controller replica does not stop control.
3. Loss of one NATS server does not lose acknowledged control state or stop the
   local control quorum.
4. A Region continues admitted safety work during GRU or WAN loss from its last
   signed `RegionSpec` and local journal.
5. Existing Dashboard, Database API, and TerraBase workloads continue serving
   when Orchestrator or NATS control is unavailable.
6. Every cloud mutation has one durable intent, one owner, one generation, one
   idempotency identity, and one recoverable outcome.
7. A timeout or lost response never means an OCI operation failed.
8. Tags support inventory and mismatch detection. They never authorize
   adoption, mutation, attachment, deletion, or ownership.
9. NATS carries configuration and control state only. Customer data and
   TerraBase correctness never enter it.
10. Autoscaling follows admission and backpressure. It never substitutes for
    immediate noisy-neighbor protection.
11. Every release uses immutable digest-bound artifacts. Rollback selects
    retained qualified bytes and never rebuilds them.
12. A Region becomes customer-selectable only after exact qualification and
    owner approval.
13. GRU eventually holds a complete ordered copy of every regional control
    journal. During a partition, the regional quorum is temporarily the only
    place that can hold new regional facts.
14. Recovery never starts a competing controller generation beside an
    authority that might still be alive.
15. No availability, recovery, scale, cost, or production-readiness statement
    exists without a candidate-bound receipt.
16. A production upgrade never mutates an active allocation in place. A failed
    candidate changes and removes only its green generation.
17. Every schedulable resource reports which desired generation it observed,
    why it is or is not ready, and whether deletion or rollout is blocked.
18. Host pressure, crash loops, reconnect storms, and consolidation cannot
    create unbounded work or bypass availability and disruption policy.
19. Development composition and development trust material cannot enter the
    production build graph, dependency graph, runtime, package, or deployment.

## Non-goals

This mission does not build:

- Kubernetes, Nomad, Helm, CRDs, CNI, CSI, or compatibility with their APIs;
- a general public cloud-control API;
- a public exec, SSH, raw host, or arbitrary systemd API;
- a customer data proxy or database gateway;
- a database leader, primary, commit authority, or membership shortcut;
- TerraBase replication, repair, anti-entropy, CRDT merge, causal progress, or
  usage accounting;
- Better Auth, Organizations, Projects, Users, Payments, entitlements, or MCP
  product policy;
- a payment processor or payment state machine;
- a source-control or artifact-registry service;
- an infrastructure state owner beside Orchestrator;
- an embedded development host, local product lab, or production `dev` mode;
- in-place mutation of an active production allocation during release;
- Pulumi or OpenTofu runtime reconciliation;
- x86 global or regional control-plane servers in the first production shape;
- automatic customer publication of a discovered Region;
- a control-plane failover Region outside GRU; or
- NATS transport for TerraBase data, public SDK traffic, billing truth, or
  customer tenant queues.

## Vocabulary

`Global Master` is the active replica in the three-replica GRU global
Orchestrator group. It owns global desired state and global operations. The
term never names a TerraBase role.

`Regional Orchestrator` is one logical three-replica control group for one
canonical `RegionCode`.

`Regional Leader` is the replica holding the current term-bound authority
claim committed by the Region's local JetStream quorum.

`RegionSpec` is the immutable, signed, generation-bound projection of accepted
global policy that one Region may execute.

`Regional Journal` is the authoritative ordered record of regional operations,
provider observations, host allocations, and receipts.

`Survival Policy` is the signed subset of a `RegionSpec` that states which
actions an isolated Region may perform and the ceilings that apply.

`Qualified Region` is a deployed Region that passed its runtime, identity,
routing, isolation, recovery, load, and rollback gates and received owner
approval.

`Provider observation` is a typed fact read from OCI. Configuration cannot
rewrite it. A reconciliation plan must account for it.

`Committed operation` is an operation that crossed its durable authorization
boundary. A new leader resumes the same operation and target instead of
inventing a replacement.

`Regional blue-green deployment` creates a complete candidate generation next
to the active generation in one Region. The candidate receives no production
traffic until it passes the role-specific health and test gates and a durable
routing generation switches traffic atomically.

`Observed generation` is the desired resource generation that a controller or
host agent has actually evaluated. Status from an older generation cannot
prove the current specification ready.

`Digest quarantine` is a durable hold on an artifact and configuration pair
that exceeded its bounded restart or health-failure policy. A new placement
cannot retry the pair until policy-authorized evidence or an operator clears
the hold.

## Stable contract identifiers

The IDs in this file are permanent. A replacement decision marks an ID
superseded and adds a new ID. It never changes the old meaning in place.

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

## System ownership

| Component | Ownership |
| --- | --- |
| Global Orchestrator | Global policy, Region catalog proposals, accepted releases, global NATS schema, budget ceilings, signed `RegionSpec` generation, global operation coordination, and regional journal aggregation |
| Regional Orchestrator | Regional NATS, OCI actuator, hosts, allocations, volumes, local routing backends, certificates, repair orchestration, autoscaling, regional release execution, and regional journal |
| Host agent | Exact allocation execution, containerd and systemd interaction, local observation, health, drain, secret materialization, and orphan reporting |
| TerraBaseV2 | Database commits, causality, CRDT merge, replication, membership acceptance, repair, anti-entropy, snapshots, split and merge, retirement safety, and usage truth |
| Database API | Public database and reactive API, authorization admission, and sole QUIC TBEP gateway |
| Dashboard | Better Auth, Organizations, Projects, Users, Payments, Streamable HTTP MCP, and customer workflows |
| NATS | Orchestrator consensus storage, typed control delivery, control discovery, and operational request-response |
| OCI | Observed compute, network, storage, Vault, Object Storage, and work-request truth |
| Cloudflare | Observed public DNS, load-balancer pool, origin, health, and routing truth |
| Forgejo and OCI Registry | Candidate source revisions, build inputs, immutable artifacts, and provenance inputs before Orchestrator admission |

Development composition is outside the Orchestrator repository and production
solution. External development tooling may consume generated, versioned
Orchestrator contracts. Orchestrator never references, builds, launches, or
packages that tooling, and no development-only service registration exists in
the production executable.

The Orchestrator never turns a projection into a second authority. OCI remains
authoritative for whether an OCI resource exists. Cloudflare remains
authoritative for observed edge configuration. TerraBase remains authoritative
for database membership and recovery frontiers. The control plane records what
it wants and what it observed, then reconciles the difference.

## Control hierarchy

```text
GRU global authority
  three global controller replicas
  one active Global Master
  global JetStream R3 domain
            |
            | signed RegionSpecs, commands, releases, ceilings
            v
regional authority for each RegionCode
  three regional controller replicas
  one active Regional Leader
  regional JetStream R3 domain
            |
            | exact allocations and provider operations
            v
regional host agents and provider actuators
            |
            +-> trusted first-party OCI containers
            +-> unprivileged tenant OCI containers
            +-> admitted host-native control roles
```

The GRU global group and GRU regional group are separate authority scopes and
separate three-replica deployments. A global controller cannot execute an
ordinary GRU provider mutation. It emits an authorized GRU `RegionSpec` or
regional operation request. The GRU Regional Leader executes it through the
same regional path used in every other Region.

## Production topology

### GRU global cell

GRU runs:

- three global-controller replicas on separate OCI fault domains;
- three GRU regional-controller replicas on separate compute;
- three dedicated ARM64 control-NATS VMs, each running one global-domain server
  process and one GRU regional-domain server process;
- one encrypted Block Volume per NATS server process, with independent global
  and GRU regional accounts, identities, streams, KV buckets, consumers, ports,
  cgroups, filesystems, and storage;
- OCI Vault and Object Storage roots needed for control recovery; and
- private Cloudflare, OCI, Forgejo, and registry actuators behind scoped
  identities.

The global controllers are stateless outside NATS and bounded local caches.
`CI.Standard.A1.Flex` OCI Container Instances are the preferred low-cost shape
only after GRU proves ARM64 availability, fault-domain placement, private
networking, restart behavior, resource identity, image admission, service
limits, and leader failover. The fallback is three small
`VM.Standard.A1.Flex` instances. A release cannot mix the two forms without a
qualification receipt.

NATS never uses Container Instances because JetStream requires durable,
performance-qualified storage and explicit recovery control.

### Regional cell

Every non-GRU production Region starts with three ARM64 controller hosts. Each
host runs one regional-controller replica and one regional NATS server. The
three hosts occupy separate availability domains where the Region has them,
otherwise separate fault domains.

NATS has:

- a dedicated encrypted Block Volume per server;
- an independent filesystem and mount namespace;
- reserved CPU and memory;
- higher CPU and I/O scheduling weight than the controller;
- a memory minimum and a protected out-of-memory score;
- bounded file descriptors, PIDs, store bytes, stream bytes, and catch-up
  bandwidth; and
- alerts before controller pressure can threaten quorum.

Controller and NATS cohosting is a cost choice, not permission to share a
process, account, credential, filesystem, or failure identity.

### Region ceiling

The catalog accepts at most twenty active Regions. All code, subjects, tests,
state, and algorithms must support that limit without hard-coded GRU/SFO/FRA
branches. Initial production qualifies GRU, SFO, and FRA. Later Regions enter
one at a time after the twenty-Region simulator passes and the real Region
produces its own evidence.

Internal and public product state uses canonical uppercase airport
`RegionCode` values. OCI names remain in the provider adapter. NATS subjects
use a strict lowercase token derived bijectively from the canonical code, but
payloads keep the uppercase `RegionCode`.

## Authority and consensus

JetStream R3 is the only Raft implementation in the Orchestrator control
plane. The three Orchestrator replicas are clients of the local quorum. They do
not maintain a second replicated log.

An authority claim contains at least:

```text
AuthorityClaim {
    scope
    term
    controller_id
    session_id
    issued_at
    expires_at
    prior_kv_revision
    build_digest
    protocol_generation
}
```

The local JetStream KV compare-and-swap commits the claim. A controller may
mutate only while it holds the newest live term, observes a healthy local
quorum, uses the matching session and build, and has not observed a newer term.
The initial target is a 15-second lease renewed every 5 seconds. Qualification
may tighten these values. It cannot lengthen them without proving the stale
writer and WAN-fault bounds.

Clock uncertainty, quorum uncertainty, a future term, an ambiguous KV result,
or a mismatched protocol generation makes the controller read-only. Server
timestamps and bounded monotonic elapsed time validate leases. A host wall
clock alone cannot extend authority.

Leadership grants permission to advance control state. It does not grant a
TerraBase vote, an OCI operation, a secret, or a destructive action. Each of
those still needs its domain-specific persisted authorization.

## NATS control network

NATS is mandatory for Orchestrator v2. It is not mandatory for TerraBase.
Replacing NATS requires a new goal and ADR because it would replace the
selected consensus and journal implementation.

The control network is a NATS supercluster:

- GRU owns one global JetStream domain;
- every Region owns one regional JetStream domain;
- each domain has three file-backed replicas inside that Region;
- gateway links route approved subjects between domains;
- no JetStream Raft group spans a WAN link;
- regional clients connect to their three local endpoints; and
- GRU clients connect to the three dedicated GRU endpoints.

A gateway failure isolates distribution, not local consensus. A regional
quorum continues accepted survival work. GRU continues global work that does
not require a current observation from the isolated Region. Any global action
that could destroy, shrink, replace, publish, or roll out in that Region holds
until its journal completeness watermark is current.

### Subject and account model

The fresh control root is `ts.orch.v2`. The v1 root cannot share authority or
consumers with v2.

Subject families are closed and generated from a checked-in protocol manifest:

```text
ts.orch.v2.global.desired.>
ts.orch.v2.global.release.>
ts.orch.v2.global.query.>
ts.orch.v2.<region>.desired.>
ts.orch.v2.<region>.command.>
ts.orch.v2.<region>.observation.>
ts.orch.v2.<region>.operation.>
ts.orch.v2.<region>.query.>
ts.orch.v2.<region>.audit.>
ts.orch.v2.<region>.agent.<agent-hash>.>
```

Accounts and identities separate:

- NATS infrastructure administration;
- global authority;
- global directory read service;
- one regional controller scope per Region;
- host agents;
- CI coordinators and isolated runners;
- read-only monitoring; and
- break-glass recovery.

No wildcard permission may cross a Region boundary by accident. Host-agent
subjects use a fixed hash of the admitted agent identity. Customer-provided
text never becomes a subject token.

Server routes and gateways require TLS 1.3 mutual authentication. Clients use
TLS 1.3, a workload certificate, and scoped NKey or JWT credentials. Account
and user signing keys live behind the admitted key service. Credentials expire
and rotate. Raw seeds never appear in environment variables, command lines,
logs, NATS, or evidence.

### State classes

Global JetStream is authoritative for:

- global authority terms;
- Region catalog and provider mappings;
- accepted global policy and limits;
- signed `RegionSpec` generations;
- accepted artifact and release sets;
- global deployment and rollback state;
- global budgets and regional ceilings;
- complete regional journal replicas and completeness watermarks;
- Cloudflare routing intent;
- global trust and revocation generations; and
- sanitized global audit and evidence indexes.

Regional JetStream is authoritative for:

- regional authority terms;
- the last accepted `RegionSpec` and `SurvivalPolicy`;
- provider-operation journals;
- hosts, allocations, volumes, attachments, and workload observations;
- regional deployment progress;
- Member allocation and repair orchestration state;
- local certificate issuance and rotation state;
- autoscaling operations and budget consumption;
- regional outbox records awaiting GRU acknowledgement; and
- sanitized regional audit events.

KV stores current bounded state. Streams hold ordered events, commands,
operations, and audit records. OCI Object Storage holds backups, large receipts,
provenance, SBOMs, logs retained as evidence, and control snapshots. NATS Object
Store cannot become the sole backup or artifact registry.

### Message envelope

Every durable message contains:

```text
ControlEnvelope {
    schema_version
    message_id
    operation_id
    causation_id
    correlation_id
    authority_scope
    authority_term
    configuration_generation
    source_identity
    target_region
    target_identity
    issued_at
    expires_at
    payload_kind
    payload_digest
    signature
}
```

Decoders bound total bytes, nesting, collection counts, strings, identifiers,
and decompression before allocation. Unknown versions and payload kinds fail
closed. Redacted typed errors never echo an untrusted payload.

Delivery is at least once. Stable IDs, journal compare-and-swap, message-ID
deduplication, operation fencing, and same-operation resume make duplicates
safe. No code or document claims end-to-end exactly-once execution.

Request-response is limited to bounded queries, status, and operations whose
failure semantics fit an ephemeral reply. A provider mutation, deployment,
Member change, certificate rotation, or destructive action always starts from
durable intent and exposes a durable operation resource.

## Regional disconnection and reconnect

### Allowed isolated work

With a healthy local controller and NATS quorum, an isolated Region may:

- restart an admitted workload;
- replace a failed workload or host;
- scale out within its signed ceiling;
- expand storage;
- repair allocations;
- renew identities under its admitted regional issuer;
- roll back to a locally retained qualified digest;
- maintain local routing backends;
- execute already committed provider operations; and
- orchestrate TerraBase replacement, catch-up, repair, and recovery through
  TerraBase's own protocols.

The Region may continue this safety work for the full outage. The policy does
not contain a short wall-clock switch that turns an otherwise healthy Region
off. Credential profiles, issuer delegation, artifact retention, reserved
capacity, and hard ceilings must support at least a thirty-day disconnection.

### Forbidden isolated work

An isolated Region cannot:

- accept a new global policy or release;
- admit an unknown artifact digest;
- publish or remove a customer-visible Region;
- add the Region to a customer database;
- change another Region;
- widen IAM or NATS permissions;
- rotate a global trust root;
- delete quarantined TerraBase data;
- perform ordinary cost-driven scale-in;
- reduce RF=2, backup, PITR, system Project, or recovery headroom; or
- exceed its signed hard provider and cost ceilings.

### Merge after reconnect

Reconnect is a journal reconciliation, not last-writer-wins configuration.

1. The Region proves its current authority term and last accepted global
   generation.
2. It uploads every unacknowledged regional event in journal order.
3. GRU validates identity, sequence continuity, digests, operation terms, and
   provider evidence.
4. GRU records a completeness watermark before issuing destructive or rollout
   work to that Region.
5. GRU compiles current global intent against the uploaded journal and fresh
   OCI, Cloudflare, host, and TerraBase observations.
6. The Region receives a new signed `RegionSpec` containing an explicit
   reconciliation plan.
7. Destructive changes wait for drain, retention, membership, and safety gates.
8. Both sides record the same terminal generation and receipt.

GRU desired configuration wins policy conflicts. Regional resource identities,
provider outcomes, accepted local allocations, committed safety operations,
and TerraBase observations remain facts. A plan may retire or replace them
only through their normal safe state machines.

## Bootstrap and disaster bootstrap

The Orchestrator repository owns one `bootstrap` command. It uses typed OCI,
Cloudflare, Vault, Object Storage, and registry clients. It does not invoke
Pulumi, OpenTofu, Terraform, shell templates, or an external reconciler.

The unavoidable external prerequisites are:

- an OCI tenancy with GRU subscribed;
- one owner-controlled short-lived OCI bootstrap credential;
- a trusted machine or independent Forgejo recovery runner to execute the
  exact signed Orchestrator binary;
- the Cloudflare account and a credential reference when public routing is in
  the selected bootstrap scope; and
- approved account, Region, CIDR, domain, budget, and recovery inputs.

`SM-ORCH-BOOTSTRAP` performs:

```text
preflight and exact target inventory
-> generate BootstrapGeneration and signed local write-ahead record
-> create the bootstrap Object Storage ledger as the first cloud resource
-> upload and verify the write-ahead chain
-> create compartments, network, IAM, Vault, keys, registry, and recovery stores
-> create GRU NATS storage and servers
-> establish global and GRU regional JetStream R3 quorums
-> create and enroll global and GRU regional controller replicas
-> transfer the complete resource ledger into NATS
-> prove exact OCI, NATS, identity, backup, and restore state
-> commit a signed BootstrapHandoffReceipt
-> revoke or expire the bootstrap credential
```

The first operation has a narrow unavoidable local-durability window. The
bootstrap command fsyncs its signed write-ahead record before the OCI call and
refuses to continue if it cannot durably create and verify the remote ledger.
Loss during that window requires owner reconciliation of the exact bucket. It
never authorizes a fresh generation to guess or adopt it.

Every create uses a deterministic generation-bound name, stable operation ID,
supported OCI retry token, and exact compartment. A lost response is observed
before retry. Existing resources outside the same signed generation are
unknown, not reusable. A bootstrap retry resumes the same generation.

Disaster bootstrap requires a higher recovery generation, signed owner
authority, proof that the prior global NATS quorum cannot recover, restored
control snapshots, and fencing of every prior global and regional term. It
cannot seed a second live global master while GRU authority might remain.

## Cloud ownership and OCI boundary

After bootstrap, Orchestrator is the sole TerraScale infrastructure state
owner. NATS stores accepted intent, resource identity, operation history, and
observations. OCI remains the external observed truth.

The OCI adapter supports at least twenty usable provider Regions while only
owner-approved qualified Regions enter the TerraScale catalog. Provider-neutral
domain models contain no OCID, OCI shape name, availability-domain string,
fault-domain string, work-request payload, or OCI retry token. The adapter
translates typed intent at the boundary.

Every environment and Region has a dedicated compartment and a regional
actuator identity. Policies enumerate exact resource types and actions. A
regional identity cannot create IAM roots, mutate another Region, change
global networking, read unrelated secrets, or exceed its compartment.

The Global Master stores policy and issues signed intent. It does not hold
ordinary SFO, FRA, or future-Region mutation credentials. Regional actuators
execute OCI operations through workload identity or short-lived scoped
credentials.

### Provider operation state machine

`SM-ORCH-PROVIDER-OPERATION` follows ADR 0020:

```text
Proposed
-> Prepared
-> AuthorizedForProviderCall
-> DispatchRecorded
-> ProviderPending | OutcomeUnknown
-> Observed
-> Verified
-> Succeeded | Held | Failed | ReconciliationRequired
```

`AuthorizedForProviderCall` is the irreversible control commit. It freezes the
action, target or deterministic create key, desired terminal state, payload
digest, request identity, allowed compensation, evidence, approvals, deadline,
and authorizing term. A new leader resumes that exact operation.

Provider adapters contain translation and typed observation. They do not hide
business policy, retries, ownership, compensation, or deletion decisions. Raw
provider responses never enter NATS, telemetry, receipts, fixtures, or errors.

### Resource ownership

Every owned OCI resource binds:

- `BootstrapGeneration`;
- `ResourceId` and provider OCID;
- Region and compartment;
- resource kind;
- owning controller and state machine;
- creation operation;
- desired and observed generation;
- lifecycle and retention class;
- immutable template or image identity; and
- last verified observation.

Tags repeat a non-secret subset for inventory. A matching tag without the
authoritative record cannot grant ownership. An authoritative record with a
mismatched provider observation holds and alerts.

## Region lifecycle

The initial provider mapping is:

| `RegionCode` | OCI Region |
| --- | --- |
| `GRU` | `sa-saopaulo-1` |
| `SFO` | `us-sanjose-1` |
| `FRA` | `eu-frankfurt-1` |

The Orchestrator discovers subscribed OCI Regions and proposes candidates. It
never publishes discovery directly.

`SM-ORCH-REGION-ADMISSION` requires:

1. owner-approved canonical `RegionCode` and immutable provider mapping;
2. compartment, IAM, network, Vault, Object Storage, budgets, service limits,
   capacity, and failure-domain inventory;
3. three regional controller and NATS hosts;
4. regional JetStream R3, gateway links, backup, and restore proof;
5. host-agent and regional actuator enrollment;
6. Dashboard and Database API with two instances each in separate failure
   domains;
7. Dashboard system Project TerraBase Members caught up and Merkle verified;
8. workload identity, trust rotation, and denial evidence;
9. TerraBase replication, Member loss, complete Region loss, restore, and
   reconnect evidence;
10. Cloudflare global and strict regional routing, health, drain, and rollback;
11. observability, paging, capacity protection, and cost evidence;
12. release, rollback, security, deletion, and disaster receipts; and
13. explicit owner approval for catalog publication.

Provisioning, qualification, and publication are separate durable stages. A
failed gate leaves the Region private and reports the exact failure.

Region removal fences new placement and routing before it drains sessions and
workloads. It retires TerraBase seats only through overlapping membership
epochs, completes retention and deletion obligations, removes active and
temporary copies under policy, verifies Cloudflare and OCI absence, and writes
final receipts. A retired `RegionCode` remains reserved forever.

## Host and workload lifecycle

Every Orchestrator control host runs an ARM64 Linux image. Workload hosts use
the architecture fixed by their admitted descriptor. ARM64 is the initial
default, but the scheduler, images, host lifecycle, and artifact admission must
also qualify x86_64 TerraBase Members and mixed-architecture replica sets as
required by the workspace goal.

Each compute host runs systemd, containerd, cgroups v2, the TerraScale host
agent, OpenTelemetry collectors, and the exact drivers required by its node
class. Images are immutable, versioned, signed, and replaced rather than
repaired in place.

Node classes separate:

- global control;
- regional control and NATS;
- trusted TerraBase Members;
- trusted Dashboard and Database API services;
- observability and CI roles where dedicated placement is required; and
- tenant-worker hosts for unprivileged tenant containers.

Tenant workers never share hosts with TerraBase or control roles. First-party
and tenant artifacts are digest-pinned OCI images. Systemd runs only admitted
host-native roles such as the host agent, containerd, and NATS. There is no
arbitrary unit text, executable path, host path, device, capability, or
privileged-container field.

`SM-ORCH-HOST-LIFECYCLE` records request, provider authorization, creation,
identity enrollment, attestation, image generation, health, scheduler
admission, cordon, drain, retirement, and provider termination. A host cannot
receive allocations before identity, image, network, clock, storage, runtime,
observability, and resource inventory pass.

Host agents use local NATS through mTLS and scoped NKey or JWT credentials.
They accept commands only for their identity, current generation, allocation,
term, and deadline. They expose observations and typed progress, not an
interactive shell. Emergency SSH is a separate break-glass procedure.

Each host reports physical capacity and the exact deductions used to derive
allocatable capacity for CPU, memory, ephemeral storage, persistent attachment
slots, network bandwidth, IPs, ports, PIDs, and file descriptors:

```text
allocatable
  = admitted physical capacity
  - operating-system and kernel reservation
  - host-agent, runtime, and telemetry reservation
  - role-specific control or data reservation
  - pressure and emergency-recovery reserve
  - already committed allocations
```

The scheduler uses the lowest current verified value. It never treats provider
shape labels or yesterday's inventory as allocatable truth. Image layers,
container writable filesystems, stopped allocations, logs, and test artifacts
have separate byte budgets and high and low reclamation watermarks. Reclamation
may remove only unreferenced, reproducible content. It never removes a running
image, mounted volume, NATS state, TerraBase state, current evidence, or the
only rollback artifact.

Host status uses closed conditions for identity, runtime, network, storage,
clock, readiness, schedulability, shutdown, and CPU, memory, disk, PID, and
network pressure. Every condition records status, reason, redacted detail,
transition time, and `observedGeneration`. Heartbeat freshness is a separate
fact and never authorizes eviction or deletion by itself.

`SM-ORCH-NODE-PRESSURE` first makes the host unschedulable, then reclaims safe
ephemeral content, asks workloads to reduce optional use, and starts a
priority- and disruption-aware drain when pressure remains. Planned shutdown
commits a durable drain, acquires a bounded system shutdown inhibitor, stops
new placement, and waits for role-specific shutdown evidence before releasing
the inhibitor. A forced kernel or provider termination records which grace and
durability gates could not complete and starts failed-host recovery. It never
pretends the graceful path passed.

`SM-ORCH-WORKLOAD-RESTART` counts failures by allocation, artifact digest,
configuration generation, role, and Region. Retries use exponential backoff
with jitter, a maximum delay, a rolling attempt budget, and a progress
deadline. The counter resets only after the workload passes its declared
minimum healthy time. Repeated startup, readiness, liveness, or customer-gate
failure quarantines the digest and configuration pair, stops local restart
storms, and proposes rollback or replacement. An isolated Region may apply a
regional quarantine under its signed survival policy and uploads it to GRU on
reconnect.

## Scheduler

The scheduler is a pure deterministic policy over typed desired state and
typed observations. It has no OCI, NATS, filesystem, socket, environment, or
wall-clock dependency. Adapters persist its decisions and execute them.

Every workload descriptor fixes:

- role and trust class;
- one closed execution mode and one closed priority class;
- immutable artifact digest, signature, provenance, and architecture;
- CPU, memory, disk, I/O, network, PID, file-descriptor, and port bounds;
- node class and runtime driver;
- failure-domain spread, affinity, anti-affinity, and disruption budget;
- workload identity, peers, ingress, and egress;
- volume and secret references;
- liveness, readiness, startup, drain, and shutdown contracts;
- restart backoff, retry budget, and digest-quarantine policy;
- rollout strategy, maximum surge, maximum unavailable, minimum healthy time,
  startup deadline, health deadline, progress deadline, rollback window,
  drain deadline, test suite, and compatibility policy;
- tenant, Project, database, Region, and cost identity where applicable; and
- exact configuration and protocol generations.

The closed execution modes are `SystemDaemon`, `ReplicatedService`,
`TerraBaseMember`, `TenantService`, `TenantHandler`, and `BoundedOperation`.
Only signed first-party descriptors may select the first three or the last.
Tenant services and handlers are stateless, unprivileged containers. A
descriptor cannot smuggle an executable, arbitrary systemd unit, persistent
tenant volume, or privileged workload through an unknown mode.

The closed priority classes are `ControlCritical`, `DataCritical`,
`ProductCritical`, `PlatformReserved`, `TenantReserved`, `TenantBurst`, and
`Background`. Preemption is disabled by default. It may stop only a stateless
allocation in a lower class when the victim's descriptor permits preemption,
its disruption budget remains satisfied, tenant reservation is preserved, and
the durable plan names the replacement or terminal outcome. NATS quorum,
Orchestrator quorum, TerraBase RF=2, active database state, the Dashboard
system Project reserve, and an allocation owned by another tenant's reservation
are never preemption targets.

The scheduler filters ineligible hosts, proves hard constraints, scores the
remaining set by least waste and topology health, and emits a deterministic
reason trace. A tie uses stable identities, never enumeration order. Missing,
stale, duplicate, conflicting, or incomplete observations hold placement.

Every qualified Region reserves capacity for one host loss, control quorum,
Dashboard and Database API, the Dashboard system Project, TerraBase foreground
work, WAL and compaction, replication and repair, observability, and one surge
Member per active upgrade cohort.

## Resource API, deletion, and controller queues

Every desired resource has an immutable identity, monotonically increasing
`specGeneration`, current authority term, ownership links, deletion request,
and typed specification. Every status has `observedGeneration`, controller
term, journal sequence, last successful reconciliation, and a closed set of
conditions. `Ready` is false or unknown when `observedGeneration` trails the
specification. A controller never copies desired values into status and calls
them observed.

List returns a stable snapshot with an opaque bounded page token and a declared
page limit. Watch returns ordered at-least-once changes from a durable resume
token. Clients deduplicate by resource identity, generation, and journal
sequence. A token below the retained floor returns
`ERR-ORCH-WATCH-EXPIRED` and the client performs a fresh list before resuming.
Slow clients receive a typed overload result and retry guidance. They do not
hold unbounded server memory or retention. This is a TerraScale operator and
controller contract, not a Kubernetes API or CRD compatibility layer.

Deletion is an explicit state machine, not absence from desired state. A
resource records `deletionRequestedAt` and typed `DeletionBlocker` values for
live dependents, traffic drain, workload stop, TerraBase membership, volume
attachment, backup, retention, legal hold, identity revocation, provider work,
and final observation. Blockers have one owning controller and evidence. A
controller cannot clear another domain's blocker. `SM-ORCH-RESOURCE-DELETION`
removes dependents in declared graph order, verifies every external absence,
records the receipt, and retains a tombstone long enough to reject stale
recreation or duplicate provider work. Arbitrary string finalizers and
invisible cascading deletion are forbidden.

Controller work queues are bounded by item count, bytes, tenant, Region, and
operation class. They coalesce repeated observations by resource identity,
keep durable intent separate from disposable wake-up hints, use fair priority
lanes, and apply exponential retry with jitter and deadlines. Reconnect,
provider recovery, and watch-resync storms cannot enqueue one copy per event
without a bound. Queue saturation preserves authority and durable journal
facts, slows or rejects new non-safety work, and emits one bounded condition
rather than recursively creating more work.

## TerraBase placement and Member lifecycle

A database selects one through twenty qualified Regions. Every selected Region
stores every logical Partition and accepts writes while its local TerraBase
replica set is healthy. Production uses two active Members per selected Region
and Partition across independent failure domains.

Orchestrator owns:

- accepted customer placement intent and capacity admission;
- Member workload and volume scheduling;
- failure-domain spread;
- Member and replica-epoch allocation requests;
- certificates and trusted endpoint advertisement;
- replacement, snapshot-transfer, and rebalance orchestration;
- storage expansion; and
- safe retirement requests.

TerraBase owns membership acceptance, voter epochs, commit and causal state,
replication, anti-entropy, Merkle verification, snapshots, repair, Partition
split and merge, and retirement safety. NATS only advertises accepted endpoints
and orchestration state. TerraBase Members never subscribe to NATS.

`SM-ORCH-MEMBER-ADD` allocates immutable database, Partition, Member,
`ReplicaEpoch`, workload, certificate, volume, and attachment identities before
starting a container. The new Member receives a verified snapshot and missing
deltas through TerraBase. Routing waits for stored, applied, and verified
frontiers and TerraBase's accepted overlapping membership epoch.

`SM-ORCH-MEMBER-REPLACE` creates a new identity or replica epoch. It never
reattaches erased writable state under the old causal actor. The replacement
catches up and passes dual-Merkle verification before the old seat can retire.
Generic allocation deletion cannot remove a Member.

Adding a database to a Region provisions both local seats, verifies every
Partition, joins membership, qualifies the Database API route, and only then
enables traffic. One failed local Member never weakens `RegionalDurable` from
two durable Members to one.

## Capacity and autoscaling

TerraBase and Database API enforce bounded admission, fair queues,
backpressure, and load shedding before new capacity exists. Orchestrator uses
sustained typed reports for CPU, memory, working set, storage headroom, WAL,
compaction, replication, repair, queue delay, throttling, forecast growth,
failure domains, and provider capacity.

Scale-out requires current complete evidence, hysteresis, a forecast or
sustained window, an admitted template, budget authority, provider capacity,
and recovery headroom. A single metric spike does not create a server unless a
typed emergency rule applies.

Each Region keeps enough warm headroom to survive one admitted host loss.
Scale-out creates capacity before moving stateful workloads. TerraBase remains
bounded while a new host, snapshot, and membership change complete.

Ordinary scale-in requires at least sixty minutes of measured quiet, fresh
complete observations, successful workload drain, stateful-owner approval,
backup and storage checks, no conflicting operation, and a reversible plan.
Scale-in never reduces required control quorum, TerraBase RF=2, system Project
capacity, failure-domain spread, or recovery reserve.

Consolidation and rebalance use the same safety state machine as scale-in. A
plan simulates every move, caps concurrent disruption by role and failure
domain, preserves one-host-loss and release-surge headroom, waits through a
cooldown, and proves a measured cost or capacity benefit after migration cost.
It cannot move a TerraBase Member without TerraBase acceptance or move a
workload merely to improve a packing score. A failed or stale plan stops and
recomputes from current observations. There is no continuous unbounded
reshuffle toward an ideal layout.

Policies distinguish an automatic budget, an owner-approval budget, a hard
TerraScale ceiling, and an OCI quota or account limit. Safety expansion may
cross the normal automatic budget with an alert and receipt, but never a hard
ceiling or provider limit. Non-safety work holds rather than spend without
authority.

## Storage and backups

Orchestrator owns OCI volumes, attachment identity, filesystem creation and
growth, encryption integration, snapshot requests, and host placement.
TerraBase owns files, WAL, segments, manifests, checksums, and database
correctness.

Volume operations are journaled and idempotent. One writable volume cannot
attach to two Member identities. Orchestrator never shrinks a volume. Expansion
verifies OCI size, device size, filesystem size, TerraBase-observed capacity,
and compaction and recovery headroom.

Removed TerraBase volumes remain quarantined for seven days after verified
backup, membership retirement, routing withdrawal, and owner-independent
deletion eligibility. A legal or recovery hold extends quarantine. Ordinary
autoscaling cannot delete permanent data volumes.

OCI Block Volume snapshots are secondary recovery inputs. They do not replace
TerraBase snapshots, PITR, immutable backup, mutation history, or side-by-side
restore verification. Control NATS snapshots and regional journals back up to
encrypted OCI Object Storage. The backup system targets at most five minutes
of state loss after total control-store destruction. Loss of one NATS server or
volume has zero acknowledged control-state loss.

## Network and routing

Private regional VCNs, dynamic routing gateways, remote VCN peering, service
gateways, regional subnets, network security groups, and private DNS carry
control and product traffic. NATS, TBEP, Member replication, provider
actuators, host agents, and secret retrieval have no public listener.

Before a container starts, the regional authority commits an allocation lease
for every private IP, protocol, interface, and port binding. The host agent
creates the network namespace and enforces the admitted ingress peers, egress
destinations, DNS policy, bandwidth, and connection limits from that lease.
Leases are unique within their routing scope, term-bound, and reconciled
against containerd, host networking, OCI network interfaces, Cloudflare
origins, and live sockets. Stop and deletion release a lease only after the
allocation and external bindings are absent. Unknown or conflicting ownership
holds reuse. Tenant text never selects a host port or network-security rule.

Network policy uses TerraScale's typed allocation contract and OCI and Linux
adapters. It does not implement CNI or expose arbitrary network plugins.

TerraBase uses direct authenticated QUIC between Members. Database API is the
sole QUIC and FlatBuffers TBEP gateway. Orchestrator and NATS never proxy either
path.

Cloudflare provides public Dashboard and Database API routing. Orchestrator
owns pool, origin, health-check, drain, regional enablement, strict regional
routes, and rollback intent through a scoped adapter. Cloudflare is observed
truth for the edge. It is not the private NATS or TerraBase network.

Global and strict routing updates are journaled, idempotent, observed after
write, and bound to a configuration generation. A Region cannot receive public
traffic before its catalog generation is owner-approved. The adapter rejects a
twenty-first active Region.

## Identity, trust, and secrets

OCI Vault or KMS protects global root and account-signing keys. Regional
intermediate issuers have Region-scoped capabilities and cannot issue a global
administrator or another Region's identity. Workload certificates are
short-lived, audience-bound, role-bound, and rotated before one third of their
lifetime remains.

Trust rotation uses two-generation overlap. A new bundle reaches every
required verifier before any new-only credential appears. Retirement waits for
current observations from all required Regions. Wrong identity, stale
generation, expired credential, replay, revoked key, and cross-Region use fail
closed.

Secrets stay in the admitted secret service and arrive through encrypted,
owner-private runtime files or equivalent kernel-protected delivery. Desired
state stores a reference, version, purpose, and allowed principal. It never
stores secret bytes.

The Dashboard system Project bootstrap follows the workspace goal. Orchestrator
provisions fixed system identities, a short-lived X.509 workload identity, a
local rotated trust bundle, and a signed, replay-protected `BootstrapGrant`
limited to idempotent work on those fixed identities. It cannot access a
customer Project or become a permanent root path.

## Delivery and upgrades

Forgejo revisions and webhooks are candidate inputs. Git is not the live
control authority. GRU verifies source, schema, signatures, dependency graph,
artifact digest, provenance, SBOM, vulnerability disposition, configuration,
migration, architecture, compatibility, and rollback anchor before committing
an accepted release to global NATS.

Build once, verify once, and deploy the same bytes. Rollback points to a
previously qualified digest and configuration. `latest`, mutable tags, rebuild
on rollback, and CI direct mutation of runtime infrastructure are forbidden.

The Orchestrator repository retains one minimal independent Forgejo recovery
workflow and runner so it can rebuild and recover the control plane. Product
CI and delivery are Orchestrator-native after bootstrap.

Every production release uses `SM-ORCH-RELEASE` independently in each Region.
There is no all-Region activation barrier. One Region's failure holds that
Region and later waves without changing a healthy Region that has already
completed its own durable cutover.

The release state machine is:

1. Freeze the exact artifact digests, configuration, schema, protocol,
   migration, test-suite, rollback, and routing identities.
2. Record the current allocation and routing generation as blue. Blue remains
   immutable, fully serving, and eligible for immediate rollback.
3. Allocate a separate green generation beside blue with enough admitted surge
   capacity to preserve the role's availability and failure reserve.
4. Keep green outside production routing while startup, readiness, liveness,
   compatibility, authorization, mTLS, tenant isolation, network policy,
   dependency, storage, capacity, and observability checks run against the
   exact candidate.
5. Run role-specific synthetic customer journeys through a strict candidate
   route. Dashboard, Better Auth, Database API, TerraBase, system Project,
   public routing, rollback controls, and denial behavior must produce the
   expected receipts. A green process that only answers a shallow health probe
   is not qualified.
6. Keep every required green allocation healthy for its declared
   `minimumHealthyTime`. Fail if startup, health, or total progress exceeds its
   deadline or if any required receipt is missing, stale, or bound to different
   bytes.
7. Commit one regional routing generation with compare-and-swap against the
   current blue generation, then switch new traffic atomically to green.
   Conflicting edge, service-discovery, or allocation state aborts the switch.
8. Drain blue sessions and keep the complete blue generation available for the
   declared rollback window. A guardrail failure switches routing back through
   another fenced generation before green is drained.
9. Retire blue only after the rollback window, current post-cutover customer
   journeys, no active sessions, no domain hold, and exact absence receipts.

The default for stateless production roles is full parallel green capacity and
`maximumUnavailable = 0`. Role policy may raise surge capacity but cannot make
an active blue allocation unavailable before cutover. A failure before cutover
removes only green. It cannot restart, rewrite, reconfigure, or drain blue.

TerraBase applies the same replacement-before-removal rule through its own
membership protocol. A candidate surge Member receives snapshot and missing
deltas, reaches stored and applied frontiers, passes causal and materialized
Merkle verification, and enters a TerraBase-accepted overlapping membership
epoch before an old Member can retire. Orchestrator does not create a second
independent writable database cluster and does not call shallow process health
blue-green qualification. Irreversible format activation follows the workspace
TerraBase ADR. After that boundary, recovery rolls forward or restores a new
cluster rather than starting an old binary on new bytes.

Global and regional controllers replace one follower at a time, prove N/N-1
protocol and state compatibility, transfer leadership deliberately, and
replace the old leader last. A new controller becomes eligible before its old
replica stops. NATS replaces one server at a time and waits for the new server
to join the intended domain, catch up JetStream state, pass storage and route
checks, and restore full R3 health before another server changes. Neither
procedure may form a competing quorum or reuse live storage identity.

Wave order limits failure:

1. isolated process and disposable OCI verification;
2. Dashboard system Project and bounded tenant canaries;
3. SFO;
4. FRA;
5. GRU product workloads;
6. remaining Regions in bounded waves; and
7. global-controller and NATS upgrades after product waves pass.

Each Region proves its blue-green cutover, rollback window, Dashboard,
Database API, TerraBase, authorization, routing, capacity, telemetry, customer
journeys, and post-cutover stability before the next wave.

## Operator contract

The operator API is private, typed, authenticated, authorized, bounded, and
audited. The CLI and operator views expose plans, approvals, operation progress,
holds, exact observations, receipts, and safe remediation. They do not expose
raw NATS, OCI payloads, shell, arbitrary manifests, secrets, or generic retry.

Owner approval is required for catalog publication, Region removal, trust-root
rotation, deletion of quarantined data, hard-ceiling change, break-glass access,
disaster bootstrap, and an irreversible compatibility activation. Ordinary
replacement, scale-out, bounded scale-in, volume expansion, credential
rotation, rollout, rollback, and repair run automatically inside accepted
policy.

## Observability

OpenTelemetry, Prometheus-compatible metrics, Loki, Tempo, Alertmanager,
collectors, and Grafana provide operations evidence. Regional telemetry spools
to encrypted bounded storage during WAN loss. Exhaustion samples or drops under
an explicit policy and alerts. Product traffic never blocks on telemetry.

Required views cover authority terms, NATS quorum and storage, gateway lag,
regional outbox completeness, operation stages, OCI work requests, host and
workload health, capacity and cost, TerraBase placement and recovery, Dashboard
and Database API, Cloudflare routing, identity expiry, deployment, rollback,
backup, restore, and security denial.

Telemetry is not authoritative control, provider, billing, or database state.
High-cardinality customer IDs, content, query text, credentials, raw provider
responses, and private paths are excluded or irreversibly bounded and scrubbed.

## Service objectives

The following are release targets and need exact receipts:

| SLI | Objective |
| --- | --- |
| Global control availability | At least 99.95% per calendar month at the accepted-operation boundary |
| Regional control availability | At least 99.95% per Region per calendar month |
| Controller leader failover | p99 at or below 15 seconds after one replica loss |
| One NATS server loss | No acknowledged-state loss and no control outage beyond client reconnect |
| Connected global configuration delivery | p99 at or below 30 seconds to every healthy Region |
| Regional command admission | p99 at or below 1 second after local publication |
| Host-failure detection | p99 at or below 60 seconds without using heartbeat loss as destructive authority |
| Safe replacement start | Within 5 minutes after confirmed failure and admission |
| Control backup RPO | At most 5 minutes after complete control-store destruction |
| Regional control restore RTO | At most 60 minutes after compute and storage capacity are available |
| GRU control restore RTO | At most 4 hours after GRU infrastructure is available |
| Region journal convergence | p99 at or below 5 minutes after WAN recovery, excluding journal volume beyond the admitted catch-up envelope |

There is no finite Global Master RTO while OCI GRU itself is completely
unavailable because authority never moves outside GRU. Regional control and
customer data service continue. The status channel must state the global
control freeze instead of claiming failover.

## Failure behavior

- One controller fails. The local NATS quorum commits a new authority claim.
  The old term is fenced and the new leader resumes journals.
- One NATS server fails. R3 remains available. Replacement catches up before
  the failed identity or volume retires.
- GRU or WAN is lost. Regions continue survival-policy work. Global releases,
  catalog changes, and policy changes freeze.
- A regional quorum is lost. Existing workloads serve from persisted verified
  configuration. New regional mutations stop until quorum restores.
- A stale leader calls OCI. The committed operation and provider idempotency
  identity constrain the result. The current leader observes before action.
- OCI returns a timeout. The operation becomes `OutcomeUnknown` and reads the
  work request and target before retry or compensation.
- A host disappears. Admission protects service while the regional controller
  creates capacity and domain controllers restore state.
- NATS is deleted. TerraBase and APIs keep serving. Control restores into a new
  generation from Object Storage and exact provider observations.
- A Region reconnects. Its journal uploads first. GRU rebases desired state
  against facts and sends a safe reconciliation generation.
- GRU storage is destroyed. Regional journals remain authoritative locally.
  Global restore imports the last backup, then fills each Region from verified
  sequence watermarks before destructive global work resumes.
- Cloudflare is unavailable. Existing edge configuration serves where the
  provider permits. Routing mutations hold and cannot block private data paths.
- A certificate issuer is compromised. The affected scope stops issuance,
  publishes a higher revocation generation, rotates the issuer, and proves
  denial before normal work resumes.
- A green candidate fails before cutover. The Region quarantines or removes
  only green, records the failing gate, and leaves blue serving with the same
  routing and configuration generation.
- A guardrail fails after cutover within the rollback window. The Region fences
  the current routing generation, returns new traffic to retained blue, drains
  green, and records the exact exposure interval and customer result.
- A workload enters a crash loop. Bounded backoff stops rapid retries. Digest
  quarantine prevents the scheduler from moving the same failure across hosts.
- A host reports pressure or planned shutdown. Placement stops first. Safe
  ephemeral reclamation and disruption-aware drain run before any permitted
  eviction or termination.
- A reconnect or watch-resume storm fills a controller queue. Durable intent
  remains in JetStream, repeated wake-ups coalesce, and non-safety admission
  slows or refuses without exhausting controller memory.

## Security and threat model

The primary model covers trusted signed code under crash-stop, network,
provider, storage, operator-error, and credential-loss failures. A root kernel
or tenancy compromise is not made safe by a control lease. Prevention,
detection, revocation, quarantine, forensic preservation, and clean recovery
cover that separate incident.

Release security requires dependency locking, reproducible or independently
verified builds, SBOM, provenance, secret scanning, static analysis, container
scanning, signature verification, vulnerability policy, hardened images,
least-privilege IAM, mTLS denial tests, NATS permission tests, hostile protocol
tests, and independent review of provider and trust boundaries.

No live OCI, Cloudflare, deployment, or destructive storage action occurs from
tests without explicit owner authority and an exact target-scoped lease.

## Repository purity and evidence layers

The Orchestrator production repository and solution do not own local product
composition. Remove `src/TerraScale.Orchestrator/Development/`, DevHost project
or package references, `dev` CLI and configuration modes, local Podman product
supervision, development NATS cluster creation, development PKI and credentials,
fixed lab routing, development-only secret defaults, and production service
registrations that select fake providers or local product processes.

Tests may use pure fakes, deterministic simulators, and process fixtures only
from test or tooling projects. Those fixtures cannot compile into, register
with, or be referenced by the production executable. They use generated public
contracts and temporary test-owned trust material. They cannot depend on
DevHost names, ports, credentials, ownership labels, or process composition.
External workspace tooling may exercise Orchestrator's public development
contracts, but Orchestrator does not build, launch, configure, or import that
tooling.

Validation layers are:

1. pure deterministic state-machine and policy tests;
2. protocol, serialization, hostile-input, and adapter tests;
3. process-level NATS and controller tests;
4. test-owned disposable ARM64 systemd, containerd, NATS, and provider-model
   fixtures outside the production artifact;
5. target-scoped disposable OCI and Cloudflare lanes;
6. full GRU/SFO/FRA production-shape qualification;
7. deterministic twenty-Region simulation; and
8. an uninterrupted thirty-day production soak.

Fault injection covers a crash before and after every journal transition,
duplicate and reordered delivery, authority churn, clock uncertainty, NATS
loss and rebuild, gateway partition, GRU loss, regional quorum loss, provider
timeouts, delayed work requests, wrong resource identity, host loss, volume
loss, certificate expiry and compromise, Cloudflare drift, interrupted rollout,
rollback, TerraBase Member loss, complete Region loss, restore, reconnect, and
noisy-neighbor pressure.

## Execution plan

### P0: contract replacement

- Adopt this file and ADR 0033 as the active Orchestrator contract.
- Version the fresh `ts.orch.v2` protocol and stable ID registries.
- Remove optional-NATS, Git-authority, Pulumi, permanent-R3-TerraBase, old
  workload-role, Project-placement, UDS, and standalone MCP assumptions from
  active code and docs.
- Delete the complete production `Development/` namespace and every DevHost,
  `dev` mode, embedded lab, local product supervisor, development NATS, PKI,
  credential, port, route, ownership-label, build, service-registration, test,
  tooling, and documentation dependency from the Orchestrator project. Move
  required generic fakes into test-owned fixtures with no production reference.
- Freeze state ownership, envelopes, subjects, authority claims, receipts,
  provider operations, `RegionSpec`, and survival policy.

### P1: global and regional control

- Implement global and regional JetStream domains, gateway topology, R3
  provisioning, authority claims, fencing, accounts, credentials, and backups.
- Implement regional outbox, GRU journal aggregation, completeness watermarks,
  and reconnect reconciliation.
- Prove one-server, one-controller, WAN, GRU, and total-store failures.

### P2: greenfield bootstrap and OCI ownership

- Implement the bootstrap command, local and Object Storage ledger, generation,
  recovery, handoff, and bootstrap credential retirement.
- Implement provider-neutral contracts and OCI adapters for compartments,
  network, IAM, Vault, Object Storage, registry, compute, volumes, attachments,
  and work requests.
- Prove no adoption, one owner, unknown outcomes, and same-operation resume.

### P3: hosts, scheduler, and identity

- Build immutable ARM64 control images and ARM64 and x86_64 workload images,
  host agents, containerd drivers, node classes, deterministic scheduling,
  workload identity, trust rotation, secret materialization, drain, and
  replacement.
- Implement allocatable accounting, closed execution and priority classes,
  network leases, node pressure, graceful shutdown, bounded restart backoff,
  digest quarantine, ephemeral reclamation, and disruption-aware preemption.
- Implement conditions, `observedGeneration`, stable paginated list, resumable
  watch, typed deletion blockers, tombstones, and bounded coalescing controller
  queues.
- Qualify regional controller and NATS cohosting under pressure.

### P4: TerraBaseV2 placement and autoscaling

- Integrate typed TerraBase Member, membership, capacity, recovery, and endpoint
  contracts.
- Implement RF=2 placement, add, replace, Region add and removal, volume growth,
  reserved capacity, autoscaling, and Cloudflare routing.
- Prove NATS never enters the TerraBase data or correctness path.

### P5: product workloads and delivery

- Deploy Dashboard and Database API twice per Region, provision the system
  Project, and qualify its bootstrap.
- Implement artifact admission, native CI, mandatory regional blue-green,
  strict candidate routes, role-specific tests, fenced routing generations,
  rollback windows, N/N-1 controller compatibility, and TerraBase surge
  upgrades.
- Remove standalone Platform, Authentication, Payments, and MCP roles after
  their owning cutover receipts pass.

### P6: operations and security

- Complete operator APIs, approvals, audit, observability, paging, backups,
  restore, break-glass, incident, compliance, retention, and deletion flows.
- Complete safe consolidation and rebalance planning, dependency-aware
  deletion, watch-resync overload, pressure, shutdown, crash-loop, and network
  lease incident flows.
- Perform independent security review and every destructive fault lane on
  disposable targets.

### P7: production qualification

- Qualify GRU, SFO, and FRA control infrastructure on the exact ARM64 and
  storage shapes.
- Qualify TerraBase placement on ARM64, x86_64, and mixed-architecture Members
  using the workspace candidate and storage profiles.
- Pass service objectives, capacity and cost ceilings, Region loss, restore,
  reconnect, blue-green qualification, cutover, rollback window, system
  Project, and customer journeys.
- Run the thirty-day soak and retain complete release evidence.

### P8: catalog expansion

- Pass the twenty-Region simulator.
- Add and qualify real Regions one at a time.
- Require owner approval for each catalog publication.

## Acceptance criteria

### AC-ORCH-001: one authority model

Active goals, ADRs, code, subjects, runbooks, and tests agree on permanent GRU
global authority, three-replica groups, local JetStream R3 consensus, regional
autonomy, and no second Raft or infrastructure state owner.

### AC-ORCH-002: safe regional autonomy

A GRU and gateway outage leaves every healthy Region able to restart, replace,
scale, expand, repair, renew, and roll back within signed limits. It cannot
invent global policy or perform forbidden destructive work.

### AC-ORCH-003: deterministic reconnect

Regional journals upload without gaps or duplicates. GRU records completeness,
preserves provider and TerraBase facts, computes one safe plan, and converges
both sides on one generation.

### AC-ORCH-004: control durability

R3 loses no acknowledged state after one server or volume loss. Backup, total
destruction, corruption, restore, new generation, and stale-controller fencing
pass in global and regional domains.

### AC-ORCH-005: greenfield bootstrap

One exact Orchestrator binary creates the estate from approved prerequisites,
survives interruption at every step, transfers a complete ledger to NATS,
retires bootstrap authority, and never adopts an unknown resource.

### AC-ORCH-006: provider safety

Every OCI and Cloudflare mutation has durable authorized intent, exact scope,
one owner, stable retry identity, bounded permissions, lost-response recovery,
and one verified terminal outcome.

### AC-ORCH-007: host and workload safety

Only admitted artifacts and roles run. Wrong architecture, digest, identity,
port, volume, secret, node class, or failure domain fails before execution.
Drain, crash, restart, and orphan recovery remain bounded and idempotent.

### AC-ORCH-008: TerraBase boundary

Orchestrator places RF=2 seats and capacity without deciding commits,
membership, replication, repair, causality, usage, or split and merge. NATS
deletion does not affect database correctness.

### AC-ORCH-009: autoscaling safety

Sustained pressure creates capacity within budget and provider limits. A spike,
stale metric, noisy tenant, or missing evidence cannot trigger uncontrolled
spend or unsafe scale-in. Admission protects service while scaling is pending.

### AC-ORCH-010: identity and secret safety

Enrollment, issuance, renewal, overlap, revocation, compromise, bootstrap, and
recovery pass. No secret or private key appears in prohibited outputs.

### AC-ORCH-011: immutable delivery

Every active Region runs one admitted digest and configuration. Blue remains
unchanged and serving while the exact parallel green generation passes minimum
health, real dependency, authorization, isolation, routing, synthetic customer
journey, and rollback gates. A durable compare-and-swap routing generation
performs cutover. Candidate failure, interruption, rollback window, controller
upgrade, NATS upgrade, and TerraBase surge upgrade pass without rebuild,
in-place mutation, premature old-version removal, or durability loss.

### AC-ORCH-012: Region lifecycle

GRU, SFO, FRA, one added Region, and one removed Region pass provisioning,
qualification, explicit publication, routing, data safety, retention, and final
receipts. A discovered Region never becomes public by itself.

### AC-ORCH-013: service objectives

The exact production candidate passes every control availability, failover,
delivery, RPO, RTO, replacement, convergence, and thirty-day soak objective.

### AC-ORCH-014: security and isolation

IAM, NATS accounts, mTLS, node classes, cgroups, container hardening, provider
scope, hostile input, break-glass, compromise, and noisy-neighbor tests deny
cross-scope access and preserve control quorum.

### AC-ORCH-015: operability

Operators can explain and recover every hold and operation through typed tools,
without raw provider payloads, NATS access, generic retry, or shell. Alerts and
runbooks pass quarterly drills.

### AC-ORCH-016: production GA

Every acceptance criterion in this file, the workspace TerraBase gates, SOC
and incident gates, proprietary artifact review, exact pricing and budget
approval, GRU/SFO/FRA qualification, and the thirty-day soak pass before the
first external release. There is no beta exception.

### AC-ORCH-017: production artifact purity

The production source graph, project graph, executable, container image,
configuration schema, service registrations, packages, deployment manifests,
credentials, and runtime dependency closure contain no DevHost, `dev` mode,
embedded product lab, local product supervisor, development NATS bootstrap,
development trust material, fixed lab route, development secret default, or
fake-provider runtime composition. Repository scans and binary and image
inspection prove the boundary. Generic fakes exist only in test-owned projects
and cannot load through production composition.

### AC-ORCH-018: workload and node safety

Closed execution modes and priority classes reject unknown behavior. Exact
allocatable accounting, unique network leases, node pressure, planned shutdown,
ephemeral reclamation, restart backoff, digest quarantine, preemption,
disruption budgets, and crash recovery pass under disk, memory, PID, network,
runtime, host, and provider faults without breaking quorum, RF=2, reserved
capacity, another tenant's reservation, or the rollback generation.

### AC-ORCH-019: resource API and deletion safety

Conditions and `observedGeneration` never report stale desired state ready.
List pagination is stable. Watch resumes without missing durable changes,
deduplicates replay, and requires a fresh list after retained history expires.
Slow clients and reconnect storms remain bounded. Deletion holds for every
typed dependent and external fact, clears blockers only through their owners,
verifies absence, and rejects stale recreation through retained tombstones.

### AC-ORCH-020: safe consolidation

Rebalance and consolidation simulate the complete move set, cap concurrent
disruption, preserve failure and surge headroom, obtain TerraBase acceptance
for Member movement, and prove a measured net benefit. Stale evidence, a
failed move, an unavailable rollback target, or a violated budget stops the
plan without repeated reshuffling or unsafe scale-in.

## Definition of success

The mission succeeds when one retained qualification run demonstrates:

```text
an empty greenfield tenancy receives one BootstrapGeneration
the Orchestrator creates and records GRU control infrastructure

global and GRU regional groups each have three replicas
global and regional JetStream domains have R3 quorum

SFO and FRA bootstrap through signed RegionSpecs
each Region operates three regional replicas and local NATS R3

Dashboard and Database API run twice in every qualified Region
TerraBase runs RF=2 for every selected Region and Partition

one controller and one NATS server fail in every Region
leadership recovers with no acknowledged control-state loss

GRU and all gateways disappear
Regions restart, replace, scale, expand, repair, renew, and roll back locally
customer data service continues without an Orchestrator or NATS request path

regional work commits while disconnected
GRU returns and receives complete ordered journals
desired state rebases against provider and TerraBase facts
no resource or data is deleted to hide the outage

OCI responses are lost before and after every provider boundary
one exact operation reaches one verified terminal outcome

a TerraBase Member and host fail
Orchestrator allocates a new identity and volume
TerraBase catches up, verifies, accepts membership, and retires safely

capacity pressure crosses the sustained gate
new ARM64 OCI capacity arrives within budget
a hostile tenant remains bounded before it arrives

an immutable candidate rolls SFO, FRA, and GRU
blue stays unchanged while full green capacity starts beside it
green passes minimum health, dependencies, authorization, isolation,
routing, synthetic customer journeys, and exact rollback tests
a durable regional routing generation moves new traffic to green
a failed pre-cutover gate removes only green
a failed post-cutover guardrail restores retained blue bytes

one host enters disk and memory pressure while another shuts down
new placement stops, safe ephemeral state is reclaimed, and workloads drain
a repeated crash loop enters digest quarantine instead of moving host to host
allocation IP and port leases never collide or leak across tenants

a stale status generation cannot become Ready
a watch resumes after disconnect and relists after compaction
a reconnect storm remains inside bounded controller queues
a deletion request waits for every typed blocker and external absence

the production solution and artifact contain no DevHost, dev mode,
embedded local product lab, development NATS, development PKI,
or fake-provider runtime composition

control NATS is destroyed and restored into a new generation
old controllers remain fenced
regional journals refill GRU without gaps

one new Region passes every gate
the owner publishes it explicitly
Cloudflare refuses a twenty-first active Region

the thirty-day soak, security review, service objectives,
recovery drills, release evidence, and workspace GA gates pass
```

## Evidence and receipts

Release evidence binds source commit, owned paths, build identity, artifact
digest, configuration and protocol generations, environment, authority terms,
NATS stream and KV identities, provider targets, test result, approval, lease,
known gaps, and signer.

Required receipt families include Bootstrap, Authority, NATS Durability,
Regional Autonomy, Reconnect, Provider Operation, Host Lifecycle, Scheduling,
Member Placement, Capacity, Storage, Identity, Routing, Release, Rollback,
Blue-Green Qualification, Workload Restart, Node Pressure, Network Lease,
Resource Status, Watch Recovery, Deletion, Consolidation, Production Artifact
Purity, Recovery, Region Admission, Region Removal, Security, Isolation,
Service, Cost, and Soak Receipts.

Unrun is not passed. A failed or inconclusive receipt remains visible. Evidence
from RF=1, fake providers, x86 development hosts, or a different artifact cannot
qualify ARM64 production.

## Main risks and controls

| Risk | Required control |
| --- | --- |
| Permanent GRU authority creates a regional-disaster control freeze | Regional R3 autonomy, thirty-day survival resources, status disclosure, GRU backups, and tested rebuild |
| Regional autonomy conflicts with newer GRU policy | Signed ceilings, forbidden isolated actions, complete journal upload, fact-preserving rebase, and safe retirement workflows |
| Two consensus systems disagree | JetStream R3 is the only Raft system; Orchestrator uses committed claims and journals |
| NATS becomes a database dependency | Static and runtime boundary tests, cached endpoint configuration, and NATS deletion scenarios |
| Cohosted regional NATS loses resources to the controller | Dedicated volume, cgroups, reservation, priority, pressure tests, and host replacement |
| Bootstrap becomes another infrastructure reconciler | One bounded bootstrap state machine, handoff receipt, credential retirement, and no steady-state second owner |
| An empty or unknown resource is adopted after interrupted bootstrap | Exact generation, local write-ahead record, remote ledger, deterministic identity, observation, and owner hold |
| GRU desired state deletes valid outage work | Facts remain immutable observations; reconciliation uses normal drain and domain safety gates |
| Stale leader completes a provider call | Immutable authorization commit, stable request identity, scoped credentials, and same-operation resume |
| Autoscaling creates spend before safety | Admission first, sustained evidence, four budget levels, reservations, and hard provider ceilings |
| Scale-in destroys data or quorum | Long quiet window, exact observations, TerraBase veto, backup, quarantine, and no volume shrink |
| Container Instances are unavailable or unsuitable in GRU | Qualification gate and automatic `VM.Standard.A1.Flex` fallback |
| ARM-only control conflicts with x86 TerraBase qualification | Keep controllers ARM64; retain typed x86 artifact and host-driver support required by the workspace goal |
| Global control restore overlaps surviving authority | Higher recovery generation, explicit owner approval, quorum-loss proof, and old-term fencing |
| Telemetry is mistaken for control truth | Read authoritative journals and provider or TerraBase observations before mutation |
| A candidate receives traffic after only a shallow health check | Keep blue unchanged; require exact-generation dependency, authorization, isolation, routing, customer-journey, minimum-health, and rollback receipts before the routing compare-and-swap |
| Blue capacity is removed before green proves stable | Set maximum unavailable to zero for stateless production roles, retain blue through the rollback window, and require verified drain and retirement evidence |
| A crash loop moves endlessly between hosts | Bound retries with exponential backoff, count by digest and configuration, quarantine the pair, and propose rollback |
| Node pressure causes random eviction or data loss | Cordon first, reclaim only safe ephemeral content, apply priority and disruption policy, and leave TerraBase and NATS retirement to their domain state machines |
| Duplicate IP or port assignment crosses allocations | Commit one scoped allocation lease before start, enforce it at the host, and release it only after verified absence |
| A watch or reconnect storm exhausts controllers | Use bounded fair queues, resource-key coalescing, durable resume tokens, compaction relist, backoff, and overload responses |
| Desired-state deletion races a live dependent | Use typed owner links and deletion blockers, domain-owned clearance, provider absence checks, and retained tombstones |
| Consolidation consumes failure or release headroom | Simulate the full plan, cap disruption, reserve host-loss and surge capacity, require net benefit, and stop on stale evidence |
| Development composition or trust enters production | Delete the production `Development/` graph and DevHost-specific fixtures, separate test composition, and inspect the source graph, binary, image, configuration, manifests, and credentials before release |

## Measured calibration

Evidence may tune controller and NATS shapes, Container Instances admission,
lease and renewal intervals, stream limits, backup interval below five minutes,
regional catch-up bandwidth, scheduler weights, warm headroom, scale windows,
volume performance, telemetry spool size, automatic budget thresholds, restart
backoff caps, pressure and reclamation watermarks, list and watch limits, queue
budgets, minimum healthy times, candidate deadlines, rollback windows,
consolidation cooldowns, and permitted surge above the required minimum.

Calibration cannot weaken authority fencing, R3, regional autonomy, TerraBase
RF=2, NATS data boundaries, provider ownership, identity scope, secret rules,
owner approval for catalog publication, maximum-unavailable safety, unchanged
blue before cutover, exact-candidate tests, production artifact purity, or
exact-digest delivery.

## References

- Workspace goal: [`../GOAL.md`](../GOAL.md)
- Repository instructions: [`AGENTS.md`](AGENTS.md)
- Foundational decision: [`docs/adr/0033-gru-global-authority-and-regional-autonomy.md`](docs/adr/0033-gru-global-authority-and-regional-autonomy.md)
- Provider fencing: [`docs/adr/0020-provider-actuator-threat-model.md`](docs/adr/0020-provider-actuator-threat-model.md)
- TerraBaseV2 production and placement ADR: [`../TerraBaseV2/docs/adr/0033-production-slos-oci-placement-and-operability.md`](../TerraBaseV2/docs/adr/0033-production-slos-oci-placement-and-operability.md)
- NATS documentation: `https://docs.nats.io/`
- OCI Container Instances shapes: `https://docs.oracle.com/en-us/iaas/Content/container-instances/container-instance-shapes.htm`
- OCI Container Instances creation: `https://docs.oracle.com/en-us/iaas/Content/container-instances/creating-a-container-instance.htm`
- OCI compute shapes: `https://docs.oracle.com/en-us/iaas/Content/Compute/References/computeshapes.htm`
- OCI Regions and failure domains: `https://docs.oracle.com/en-us/iaas/Content/General/Concepts/regions.htm`
- OCI remote VCN peering: `https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/remoteVCNpeering.htm`
- OCI Vault: `https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Concepts/keyoverview.htm`
- Comparative deployment mechanics, not compatibility targets:
  `https://kubernetes.io/docs/concepts/workloads/controllers/deployment/`,
  `https://developer.hashicorp.com/nomad/docs/job-specification/update`,
  `https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-type-ecs.html`
- Comparative node and API lifecycle mechanics, not compatibility targets:
  `https://kubernetes.io/docs/concepts/scheduling-eviction/node-pressure-eviction/`,
  `https://kubernetes.io/docs/concepts/overview/working-with-objects/finalizers/`,
  `https://kubernetes.io/docs/reference/using-api/api-concepts/`
