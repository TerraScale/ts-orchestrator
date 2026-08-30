# TerraScale Orchestrator architecture

> Superseded on 2026-08-29 by the repository [`GOAL.md`](../../GOAL.md) and
> [ADR 0033](../adr/0033-gru-global-authority-and-regional-autonomy.md). The
> repository goal's authority model — permanent GRU global authority, JetStream
> R3 as the only Raft system, NATS as the mandatory Orchestrator v2 control
> network, and the `ts.orch.v2` subject root — controls wherever this body
> disagrees. The development-topology and lab sections were removed on
> 2026-08-29 by the GOAL P0 repository-purity sweep, so historical line
> citations below that point shift accordingly. This body is not authority for
> new implementation.

Status: superseded architecture record.

Authority: repository [`GOAL.md`](../../GOAL.md), then workspace
[`GOAL.md`](../../../GOAL.md).

Target: C#/.NET 10 on systemd/containerd hosts, initially OCI ARM64 and x64.

## Mission

Build the TerraScale-specific production control plane. It schedules a closed
catalog of signed first-party workloads and policy-admitted tenant workloads,
owns infrastructure and delivery, manages Region capacity and identity, and
orchestrates TerraBase placement and repair without entering the database data
path.

It is not Kubernetes, Nomad, a public workload escape hatch, a database
coordinator, an identity provider, a payment service, an MCP service, or a
customer data proxy.

## Product ownership

| Component | Owner |
| --- | --- |
| Dashboard | One full-stack Vinext TypeScript project owning Better Auth, Organizations, Projects, Users, Payments, Streamable HTTP MCP, and customer workflows |
| Database API | Independent C#/.NET 10 ASP.NET Core service owning public database and reactive APIs and the sole QUIC TBEP gateway |
| TerraBaseV2 | Private Rust engine owning native replication, database authorization, reactive sync, usage accounting, and recovery |
| Orchestrator | Infrastructure, scheduling, identity, certificates, capacity, placement intent, repair orchestration, delivery, and the NATS control network |
| Public SDKs | Typed customer and reactive contracts |

The legacy Platform, standalone Authentication, Internals Payments, and
`TerraScale.MCP` workloads are migration sources. They leave the active role
catalog after direct cutover qualification.

## Control hierarchy

~~~text
global policy and release authority
            |
            v
regional controllers and durable regional state
            |
            v
host agents
            |
            +-> trusted first-party OCI workloads
            +-> unprivileged tenant OCI workloads
            +-> admitted host-native bootstrap roles
~~~

Regions keep serving, restarting admitted workloads, replacing failed hosts,
scaling within approved policy, and expanding storage during WAN or global
control loss. New global releases, catalog publication, and global policy
changes stop unless a separately authorized break-glass procedure applies.

Existing Dashboard, Database API, and TerraBase workloads cannot require a live
global controller or NATS lookup for every request.

## Region catalog

The initial active catalog is GRU, SFO, and FRA. Provider contracts and public
models support at least twenty Regions without hard-coded three-Region logic.

A Region becomes customer-selectable only after:

- host, network, storage, and failure-domain admission;
- regional controllers and host agents;
- Dashboard and Database API instances;
- Dashboard system Project TerraBase replicas caught up and Merkle verified;
- workload certificates, trust bundles, and rotation;
- public global and strict regional routing;
- Better Auth, OIDC, OAuth introspection, and Database API authorization;
- TerraBase live replication, anti-entropy, snapshot recovery, and complete
  Region loss recovery;
- metrics, logs, traces, alerts, and capacity protection; and
- exact release, rollback, failure, and restore receipts.

Automated gates produce an admission proposal. Public catalog publication
requires owner approval until a later explicit decision authorizes fully
automatic admission.

Region removal fences routing, drains sessions, verifies retained copies,
retires replica actors, removes active and temporary data under policy, and
records deletion receipts.

## Global product deployment

Dashboard and Database API run in every available production Region. Each has
at least two instances on independent failure domains.

The Dashboard system Project uses:

- `all-available-regions`;
- TerraBase RF=2 active Members per Region and Partition;
- immutable backup and PITR;
- reserved capacity or dedicated placement;
- `GlobalDurable` for identity, authorization, payment, entitlement, and
  bootstrap state; and
- the ordinary public Database API contract.

A customer noisy neighbor cannot stop login, authorization, payment, or
bootstrap work. Reserved capacity does not grant Dashboard a private database
operation.

## Dashboard bootstrap

Orchestrator provisions:

- fixed system Organization, Project, and database identities;
- a short-lived X.509 Dashboard workload identity;
- a locally available rotated trust bundle; and
- a signed `BootstrapGrant`.

The grant is certificate-bound, audience-bound, short-lived, replay-protected,
and limited to idempotent bootstrap operations on fixed system Project
identities. It cannot access customer Projects.

Steady state uses a rotated workload credential through the normal
`@terrascale/sdk` credential-provider contract.

Complete recovery must qualify bootstrap when Dashboard identity data is
unavailable, without introducing a permanent root key or second identity
authority.

## TerraBase placement and lifecycle

A customer database selects one through twenty active Regions. Every selected
Region stores every logical Partition and accepts writes.

Production uses two active Members per selected Region and Partition.
`RegionalDurable` requires both local Members. The database does not weaken
that requirement when one Member fails. Orchestrator replaces and catches up
the failed seat while traffic uses another selected Region when possible.

Backup is independently optional, read-only, immutable, and non-voting.

Orchestrator owns:

- Member workload and volume scheduling;
- failure-domain spread;
- replica identity allocation requests;
- capacity admission;
- certificate issuance and rotation;
- snapshot source selection and transfer orchestration;
- replacement and rebalance intent;
- storage expansion; and
- safe retirement workflows.

TerraBase owns:

- accepted membership epochs and overlapping quorum transitions;
- `CommitId`, causal actors, and counter state;
- write acknowledgement;
- replication and anti-entropy;
- snapshot and Merkle verification;
- recovery position;
- Partition splits and merges; and
- retirement safety.

An Orchestrator command, NATS lease expiry, missing heartbeat, or host tag
cannot grant a replica vote, publish an effective epoch, collect a causal
actor, or appoint a leader.

## NATS

NATS is a replaceable control adapter, not the universal platform.

It may be used for:

- versioned configuration distribution;
- service and host discovery;
- bounded health hints;
- controller request and response where its failure semantics fit;
- regional control journals or KV only after durability and recovery receipts;
  and
- non-authoritative operational notifications under typed control contracts.

NATS never carries:

- TerraBase documents, CRDT deltas, WAL, replication, repair, snapshots, query
  results, reactive payloads, or checkpoints;
- Better Auth secrets or sessions;
- payment secrets;
- authoritative usage or billing data;
- OCI images or database backups; or
- a database membership decision.

The control code depends on a typed distribution and durable-state interface,
not NATS subjects in business rules. If NATS fails its cost, isolation,
recovery, or performance gate, replace it without changing public protocols or
database state.

Complete loss of NATS may pause new configuration, scheduling, or discovery
where no alternative is available. Already admitted product workloads continue
serving. TerraBase continues reads, eligible writes, replication, repair, and
recovery from durable verified configuration.

Control-plane and customer-product NATS, when both exist, use separate
processes, trust roots, accounts, credentials, ports, cgroups, and storage.
Physical host sharing requires isolation and recovery receipts.

## Scheduler and workloads

The scheduler accepts only versioned role descriptors with:

- immutable artifact digest and provenance;
- architecture and runtime class;
- CPU, memory, disk, I/O, PID, file-descriptor, port, and network limits;
- failure-domain and anti-affinity policy;
- workload identity and allowed peers;
- storage and secret references;
- health, readiness, drain, shutdown, and restart contracts;
- update and rollback policy; and
- tenant and cost identity.

Tags cannot authorize a workload, secret, provider resource, host path, or
destructive operation.

Trusted first-party services run as signed OCI containers unless an admitted
bootstrap-critical systemd role requires native execution. Tenant workloads
run as unprivileged OCI containers with no host paths, privileged mode, control
credentials, or implicit TerraBase access.

## Capacity and noisy neighbors

Autoscaling follows sustained admitted demand. It is not the first safety
mechanism.

Database API and TerraBase enforce bounded fair queues, resource budgets,
backpressure, and load shedding before a new host exists. Orchestrator consumes
typed capacity pressure and forecasts, not raw utilization alone.

Placement preserves reserved headroom for:

- one host loss;
- Dashboard Better Auth and Database API;
- TerraBase foreground writes and reads;
- WAL, compaction, and recovery;
- Region replication and repair;
- system Project work;
- control state and host agents; and
- observability needed for incident response.

One hot tenant cannot trigger uncontrolled capacity, exhaust another tenant's
reservation, or place first-party auth and billing behind its queue.

Scale-in requires current workload drain, stateful-owner approval, storage and
backup checks, no conflicting operation, and a reversible fenced workflow.
TerraBase Members cannot be removed through generic allocation deletion.

## Storage

Orchestrator owns provider volumes, attachment identity, filesystem growth,
encryption integration, and host placement. TerraBase owns file and segment
correctness.

Volume operations are journaled and idempotent. A volume identity cannot attach
to two writable Member identities. Erased Member state receives a new
`ReplicaEpoch`.

Storage expansion verifies provider size, device size, filesystem size,
TerraBase-observed capacity, and recovery headroom before completion.

Block snapshots are secondary recovery inputs. They do not replace
TerraBase-native snapshots, mutation history, immutable backup, PITR, and
side-by-side restore tests.

## Identity and mTLS

Use established cryptographic libraries and provider KMS or Vault roots.
Orchestrator owns workload certificate profiles, issuance policy, rotation,
revocation, trust bundles, and audit.

mTLS is mandatory for:

- controller and host-agent boundaries;
- NATS routes and privileged clients when NATS is used;
- secret retrieval;
- CI worker enrollment;
- operator APIs;
- cross-Region privileged control; and
- every `TerraScale.Database` to TerraBaseV2 QUIC link, including same-host
  loopback.

Public customer HTTPS uses server TLS plus Better Auth or Project credentials.
It does not require customer client certificates.

QUIC 0-RTT is disabled for mutations.

## Delivery

Orchestrator owns native GitOps, CI runners, candidate admission, release sets,
regional rollout, health gates, rollback, and promotion.

Artifacts are immutable and digest-bound. Build once, verify once, deploy the
same bytes. A rollback selects a previously admitted digest and configuration,
not a rebuild.

Rollout order limits failure:

1. isolated verification;
2. SFO;
3. FRA;
4. GRU; and
5. remaining Regions in bounded waves after the initial catalog expands.

Each Region proves Dashboard, Database API, TerraBase, system Project,
authorization, routing, metrics, and rollback before the next wave.

The Orchestrator repository does not build product source owned by another
repository. It consumes admitted artifacts and provenance.

## Observability

OpenTelemetry, Prometheus-compatible metrics, Loki, Tempo, Alertmanager,
collectors, and Grafana provide operator observation.

Telemetry is not authoritative control, database, usage, or billing state.
Missing metrics cannot authorize a destructive operation.

Required views include:

- workload and host health;
- Region admission and routing;
- Dashboard and Database API availability;
- Better Auth latency and denial;
- TerraBase causal lag, replication bytes, repair, snapshots, compaction,
  resource pressure, and usage-export health;
- NATS adapter health when enabled;
- volume and provider operations;
- deployment and rollback;
- cost and capacity; and
- security and certificate expiry.

Regional telemetry spools under a fixed encrypted budget during WAN loss.
Exhaustion drops or samples according to explicit policy and alerts. Product
traffic never blocks on telemetry.

## Test layers

1. Pure deterministic state-machine and policy tests.
2. Process-level protocol and adapter tests.
3. Process-level NATS and controller tests from test-owned fixtures.
4. Targeted one-Region production-component lanes.
5. Disposable real systemd/containerd/provider fixtures.
6. Full production qualification and bounded rollout.

Mocks cannot qualify a destructive provider, storage, membership, certificate,
backup, restore, or deployment transition.

Required fault cases include:

- process and host crash at every journal transition;
- duplicate, delayed, reordered, and lost control delivery;
- NATS complete loss and rebuild;
- global controller and WAN loss;
- one Dashboard or Database API instance loss;
- one TerraBase Member loss under RF=2;
- complete selected Region loss and rebuild;
- certificate expiry, rotation, revocation, and wrong identity;
- volume attach, expansion, replacement, and wrong-volume denial;
- slow and hostile tenant pressure;
- interrupted release and rollback;
- Dashboard system Project complete recovery; and
- direct legacy Auth, Payments, and MCP cutover.

## Production gates

Production admission requires evidence for:

- regional autonomy and global-policy freeze;
- one-host loss within capacity headroom;
- Dashboard and Database API two-instance availability;
- Better Auth and system Project bootstrap;
- TerraBase RF=2/2, selected-Region placement, native replication, anti-entropy,
  backup, and recovery;
- multi-tenant admission before autoscaling;
- provider and storage performance;
- workload identity and secret rotation;
- immutable artifact provenance and rollback;
- authoritative usage export;
- NATS R3 durability and control-network recovery;
- compliance, retention, deletion, and audit; and
- current public SDK and contract compatibility.

An RF=1 lab, green control-plane test, or connected NATS cluster cannot satisfy
these gates.

## Non-goals

Orchestrator does not implement:

- Kubernetes, Nomad, Helm, CRDs, CNI, or CSI compatibility;
- arbitrary privileged customer containers;
- a public exec or raw host API;
- a new VPN or cryptographic algorithm;
- a database leader or mutation path;
- Better Auth, Stripe, MCP, or public SDK business logic;
- a second customer Dashboard;
- a metrics database;
- a source-control system; or
- mandatory NATS integration in TerraBase.

## Historical records

Older ADRs, receipts, and delivery documents remain evidence of prior work.
Any record requiring permanent TerraBase R3 Members, Project-level Region
placement, Platform or standalone Authentication workloads, separate MCP,
Dashboard-owned database routes, UDS TBEP, NATS-carried database correctness,
or leader transfer is superseded by the workspace `GOAL.md` and this
architecture.
