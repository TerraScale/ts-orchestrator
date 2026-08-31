# GRU global authority and autonomous regional control

- Status: Accepted
- Date: 2026-08-29
- Decision owner: TerraScale workspace owner
- Scope: global and regional authority, NATS, disconnected operation,
  bootstrap, control-state ownership, regional release cutover, and production
  artifact boundary
- Goal: [`../../GOAL.md`](../../GOAL.md)

## Context

TerraScale needs one global control authority and autonomous regional repair.
The system must deploy TerraBase into as many as twenty Regions, create OCI
capacity, operate product workloads, and reconcile failures without putting a
global controller or broker in the database request path.

The previous architecture left NATS replaceable, divided global and regional
connections into several optional configurations, treated Git as declared
intent, and assigned durable cloud foundation to Pulumi. The owner selected a
simpler production contract:

- the Global Master always lives in GRU;
- every logical Orchestrator group has three replicas and one active leader;
- NATS JetStream provides the Raft quorum and authoritative control state;
- every Region keeps operating safely while GRU is unavailable;
- GRU eventually stores all regional configuration, journals, and evidence;
- the first Orchestrator creates and owns the greenfield OCI estate; and
- Pulumi and OpenTofu do not participate;
- each Region qualifies green beside unchanged blue before traffic cutover;
  and
- development-host composition does not belong in the production project or
  artifact.

These choices create a real tradeoff. A complete GRU outage freezes global
policy, catalog, and release work because authority never moves elsewhere.
Regional control and customer data service continue. The design states that
failure rather than claiming that three hosts inside one Region solve regional
disaster recovery.

## Decision

### One hierarchy, two authority scopes

GRU runs two distinct three-replica Orchestrator groups:

1. The global group elects one Global Master and owns global policy, accepted
   release sets, Region catalog proposals, signed `RegionSpec` generations,
   global limits, Cloudflare intent, and regional journal aggregation.
2. The GRU regional group acts like every other Regional Orchestrator. It owns
   GRU hosts, workloads, volumes, local routing backends, identity operations,
   repair, and OCI mutations.

Every other Region runs one three-replica Regional Orchestrator. One Regional
Leader executes the current `RegionSpec` through the Region's provider,
scheduler, identity, and workload state machines.

Global controllers do not hold ordinary regional OCI mutation credentials.
They authorize typed regional intent. A regional leader executes that intent
with a Region and compartment-scoped identity.

### JetStream R3 is the Raft system

Every global and regional control domain uses a three-server, file-backed
JetStream cluster. JetStream's Raft consensus commits authority claims, KV
state, streams, and operation journals. Orchestrator replicas do not run a
second Raft log.

The active controller holds a monotonic term and compare-and-swap lease in its
local JetStream KV store. Mutation requires the newest live term, the matching
session and build, a healthy local quorum, and no newer observed term. Quorum,
clock, generation, or outcome uncertainty makes the controller read-only.

Leadership is necessary but insufficient for an external mutation. OCI,
Cloudflare, volume, identity, release, and TerraBase workflows still require
their persisted domain authorization and evidence.

### One global NATS network with local consensus

The NATS control plane is a supercluster. GRU owns the global JetStream domain.
Every Region owns a regional JetStream domain. Gateways carry approved global
and regional subjects, but no Raft group spans a WAN connection.

GRU NATS runs on three dedicated ARM64 VMs. Each VM runs one global-domain
NATS server process and one GRU regional-domain NATS server process. Every
process has its own encrypted Block Volume, identity, account, ports,
filesystem, and cgroup.

Each non-GRU Region starts with three ARM64 control hosts. Each host cohosts one
controller replica and one regional NATS server. NATS receives a dedicated
volume, protected memory, reserved CPU and I/O, higher scheduling priority, and
separate process, account, credentials, ports, filesystem, and cgroup.

Regional clients connect to local NATS. A gateway or GRU failure does not
break regional quorum.

The fresh subject root is `ts.orch.v2`. V1 consumers and state cannot acquire
v2 authority.

### NATS is authoritative for Orchestrator state

Global NATS owns global desired state and the aggregated control record.
Regional NATS owns regional operation state and observations. Git and Forgejo
provide candidate source revisions. OCI Registry provides candidate artifacts.
Neither becomes live authority until GRU records an admitted digest and
configuration in NATS.

OCI remains authoritative for observed provider resources. Cloudflare remains
authoritative for observed edge state. TerraBase remains authoritative for
database membership, frontiers, repair, and retirement. NATS records intent
and observations but cannot manufacture facts from those systems.

Control messages use versioned, bounded, signed envelopes with stable message,
operation, causation, and correlation IDs, authority term, configuration
generation, source and target identity, deadline, payload digest, and schema
version. Delivery is at least once. Idempotency, deduplication, fencing, and
same-operation resume make duplicates safe.

### Regional autonomy

An isolated Region may use its last signed `RegionSpec`, `SurvivalPolicy`, and
qualified artifacts to:

- restart and replace admitted workloads;
- replace failed hosts;
- scale out within signed limits;
- expand storage;
- repair allocations;
- renew existing identity classes;
- roll back to a retained qualified artifact;
- maintain local routing backends; and
- orchestrate TerraBase replacement and recovery through TerraBase protocols.

It cannot accept new global policy, admit a new digest, publish a Region, add a
Region to customer placement, widen permissions, rotate a global trust root,
delete quarantined data, perform ordinary cost scale-in, weaken durability, or
exceed hard ceilings.

Serving and safety work has no short wall-clock cutoff. The admitted identity,
artifact, reserved-capacity, and recovery design must support at least thirty
days of disconnection. Global and customer-facing changes remain frozen for
the entire outage.

### Regional release cutover is blue-green

GRU admits the immutable release set and wave order. Each connected Regional
Leader owns the exact execution and routing state for its Region. It records
the active generation as blue, creates full green capacity beside it, and keeps
green outside production routing while the goal's minimum-health, dependency,
authorization, isolation, routing, customer-journey, rollback, and role-specific
tests run.

The Region commits traffic cutover through one term- and generation-fenced
routing compare-and-swap. A failed pre-cutover candidate changes only green.
Blue remains intact through the declared rollback window. Regions cut over in
bounded waves rather than waiting at one global activation barrier.

TerraBase satisfies replacement-before-removal with surge Members, catch-up,
Merkle verification, and TerraBase-accepted overlapping membership. Controller
and NATS releases replace one replica at a time and restore full quorum before
the next replacement. The release process never creates a second writable
TerraBase cluster or a competing control quorum.

### Production composition excludes development hosting

The production project, solution, executable, container image, configuration,
and deployment contain no embedded development host, `dev` runtime mode, local
product composition, development NATS bootstrap, development PKI or credential,
fixed lab route, development-only secret default, development-host-specific
fixture, or fake-provider runtime registration. Generic fakes and process fixtures live in
test or tooling projects and cannot enter production composition.

External development tooling may consume generated versioned contracts. The
production Orchestrator does not reference, build, launch, configure, or import
that tooling.

### Reconnect preserves facts

Regional work created during a partition cannot be present in GRU until the
partition ends. The Region commits it locally and places it in an ordered
outbox. Reconnect uploads and validates the complete journal before GRU issues
destructive or rollout work.

GRU configuration wins desired-policy conflicts. It does not erase OCI
resources, committed provider operations, accepted regional allocations,
TerraBase observations, or other facts. GRU compiles a new reconciliation plan
against the uploaded journal and fresh observations. Retirement and deletion
still pass normal drain, membership, retention, and safety gates.

### Orchestrator owns bootstrap and cloud state

The exact Orchestrator binary has a `bootstrap` mode. A trusted operator or
independent recovery runner supplies a short-lived target-scoped OCI credential
and approved inputs. The command creates the bootstrap ledger, compartments,
network, IAM, Vault, Object Storage, registry, GRU NATS, controllers, recovery
stores, and optional Cloudflare foundation.

It journals before mutation, uses stable operation IDs and deterministic
generation-bound names, observes lost responses, resumes the same generation,
transfers the complete inventory into NATS, emits a signed handoff receipt, and
retires bootstrap authority. Pulumi, OpenTofu, and Terraform never become a
second state owner.

The first remote ledger creation has an unavoidable local write-ahead window.
The command fsyncs a signed local record before the call and stops if it cannot
create and verify the remote ledger. Ambiguity requires owner reconciliation.
It never permits a new generation to adopt an uncertain resource.

## Authority and state matrix

| State | Writer | Durable home | Partition behavior |
| --- | --- | --- | --- |
| Global policy and Region catalog | Global Master | GRU global JetStream | Frozen without GRU quorum |
| Accepted release and artifact set | Global Master | GRU global JetStream | Regions use retained accepted digests |
| `RegionSpec` | Global Master | GRU and target regional JetStream | Last accepted generation remains executable |
| Regional authority and operations | Regional Leader | Regional JetStream | Continues with local quorum |
| Regional provider observations | Regional actuator | Regional journal, then GRU replica | Preserved and uploaded after reconnect |
| Global edge intent | Global Master | GRU global JetStream | Frozen without GRU quorum |
| Regional edge backend observation | Regional Leader | Regional journal, then GRU replica | Local health and drain continue |
| TerraBase membership and recovery | TerraBase | TerraBase | Continues without NATS where its own quorum permits |
| Control backup | Backup controller | OCI Object Storage | Restores only into a higher fenced generation |

## Failure rules

- One controller failure elects a replacement inside the same group.
- One NATS failure preserves quorum and acknowledged state.
- GRU loss freezes global work and leaves regional safety work active.
- Regional quorum loss freezes new regional mutations while admitted product
  workloads continue from persisted verified configuration.
- A provider timeout becomes `OutcomeUnknown`, never permission for a fresh
  logical operation.
- Total control-store restoration creates a higher recovery generation and
  fences every previous controller term.
- GRU restoration imports regional journals and proves completeness before
  destructive global work resumes.

## Security consequences

- Servers and gateways use TLS 1.3 mutual authentication.
- Clients also use scoped NKey and JWT identities.
- Global, regional, infrastructure, agent, CI, monitoring, and recovery
  accounts have disjoint permissions.
- NATS never stores secret bytes, private keys, customer content, raw provider
  responses, TerraBase data, usage truth, payment data, or sessions.
- Global controllers have no routine regional provider credential.
- A compromised Region cannot use its identity in another Region.
- Break-glass and disaster bootstrap require explicit owner authority and
  retained receipts.

## Alternatives rejected

### One WAN JetStream cluster

Rejected. WAN latency and partitions would couple every regional operation to
one cross-Region Raft quorum and weaken regional autonomy.

### One GRU-only NATS cluster

Rejected. Regional autoscaling and repair could not continue during GRU or WAN
loss.

### Automatic global failover to SFO or FRA

Rejected by owner choice. It adds cross-Region fencing and split-brain recovery
that the product does not need for its first control architecture.

### Separate Orchestrator Raft beside JetStream

Rejected. Two consensus logs could disagree about leadership and committed
state. JetStream R3 is the selected consensus system.

### Git as live desired-state authority

Rejected. Git remains source and review evidence. Accepted live state,
operations, observations, and autoscaled children belong in NATS journals.

### Pulumi or OpenTofu bootstrap ownership

Rejected. A second reconciler and state file could race Orchestrator over
instances, volumes, networks, and attachments.

### Discard regional work after reconnect

Rejected. It could duplicate provider resources, interrupt valid workloads, or
delete data created by a committed safety operation.

## Compatibility and migration

The current implementation uses the `ts.orch.v2` subject root, NATS KV leases,
separate regional and global configuration types, and partial global gateway
support. V2 is a greenfield authority generation. It does not reuse v1 streams,
consumers, credentials, or leases.

The remaining greenfield rollout gates are:

1. delete the production `Development/` graph and every development-host
   runtime, trust, route, fixture, and service-registration dependency;
2. qualify the v2 implementation in test-owned and disposable environments;
3. bootstrap a fresh v2 control estate;
4. admit exact current desired state through v2;
5. prove no v1 writer can mutate v2 scope;
6. switch host agents and controllers through a fenced handoff; and
7. retire v1 credentials and stores only after rollback and evidence gates
   close.

This ADR supersedes ADR 0004's Pulumi owner, ADR 0013's Git authority after
admission, and the optional-NATS target in the previous architecture. It does
not weaken ADR 0020 provider fencing, ADR 0024 greenfield quarantine, ADR 0025
rollback, ADR 0029 stateless tenant scope, ADR 0031 tenant containers, or any
TerraBase boundary in the workspace goal.

## Required evidence

Acceptance as a document records the owner's choice. Production use still
requires:

- model tests for authority, lease, term, quorum, reconnect, and restore;
- R3 process and storage tests in every topology;
- controller and NATS cohosting pressure tests outside GRU;
- one-controller, one-server, gateway, WAN, GRU, regional-quorum, corruption,
  and total-store fault tests;
- exact regional journal completeness and fact-preserving merge receipts;
- bootstrap interruption and no-adoption proof at every mutation boundary;
- provider lost-response and leadership-change tests from ADR 0020;
- NATS permission, mTLS, key rotation, compromise, and redaction review;
- proof that TerraBase and customer APIs serve without NATS; and
- regional blue-green candidate, routing-generation, rollback-window,
  controller, NATS, and TerraBase surge receipts;
- source-graph, binary, image, configuration, deployment, and credential proof
  that development composition cannot enter production; and
- GRU/SFO/FRA production qualification and the thirty-day soak from
  [`../../GOAL.md`](../../GOAL.md).

## Consequences

The design is simple at the authority boundary. GRU always decides global
policy. A Region always decides execution inside its accepted policy. NATS is
the one control-state system. OCI and TerraBase facts remain outside it.

The cost is explicit. Every Region needs an R3 NATS and controller floor. GRU
needs dedicated global, regional, and NATS compute. Global control has no
regional failover. Regional reconciliation needs careful journal replication
and three-way planning after an outage. Blue-green needs temporary full
stateless capacity and role-specific surge capacity. Development composition
lives outside the production project. Those costs buy predictable authority,
safe release cutover, and a control failure boundary outside the customer data
path.
