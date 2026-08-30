# Architecture boundaries

The full authority is the repository [`GOAL.md`](../../GOAL.md). The workspace
[`GOAL.md`](../../../GOAL.md) controls cross-repository decisions.

## Product roles

TerraScale is product-specific. Orchestrator schedules a closed set of trusted
TerraScale roles and separately admitted tenant compute. It does not implement
Kubernetes compatibility or provide a generic cluster API.

| Role | Boundary |
| --- | --- |
| Dashboard | One full-stack Vinext TypeScript app. Owns Better Auth, Organizations, Projects, Users, Payments, entitlements, Streamable HTTP MCP, and customer workflows. |
| Database API | Independently deployable C#/.NET 10 ASP.NET Core service. Sole QUIC/TBEP gateway to TerraBase. Permanent source lives in `TerraScale.Internals`; the standalone repository is migration-only until retirement. |
| TerraBase | Private Rust database engine. Owns mutations, replication, repair, reactive sync, metrics, and authoritative usage. |
| Orchestrator | Owns infrastructure, scheduling, workload identity, database placement intent, capacity, repair orchestration, and delivery. |

Dashboard uses `@terrascale/sdk` and the same public APIs as customer
Projects. It has no direct TerraBase, TBEP, private route, or tenant bypass.

The standalone Platform, Authentication, Payments, and `TerraScale.MCP`
services are removed after direct cutover. Historical deployment records for
those roles do not authorize new implementations.

## Regional control

GRU owns the permanent three-replica global authority. Every Region owns a
three-replica Regional Orchestrator and local JetStream R3 domain. Regions
continue signed survival-policy work when GRU or the WAN is unavailable.
Global release, policy, and catalog changes freeze. Existing database reads,
eligible writes, replication, repair, and client catch-up do not pause.

The Orchestrator uses typed desired and observed state, fenced writers,
idempotent operations, immutable release identities, and durable receipts.
Host tags, load, a missing heartbeat, NATS lease expiry, or filtered inventory
cannot grant database membership or authorize destructive storage work.

## Database placement and host scheduling

Database placement belongs to each database, not to its Project. A database
selects one through twenty active Regions. Every selected active Region stores
every logical Partition and accepts writes. GRU, SFO, and FRA are the initial
catalog.

Production uses two active TerraBase Members per selected Region and
Partition, placed in independent failure domains. A backup is optional,
read-only, non-voting, and independent of active placement.

Orchestrator owns accepted placement intent and concrete host allocation.
TerraBase owns membership acceptance, replica epochs, causal actor lifecycle,
split and merge decisions, repair, and safe decommission. Scheduling pressure
may request capacity in the selected Region. It cannot add a Region, remove a
Region, spill data into an unselected Region, or appoint a leader.

## Database transport

Database API is the only TBEP client. TBEP uses generated FlatBuffers over QUIC
with mutual TLS on remote and loopback paths. UDS, raw HTTP, NATS, or a broker
cannot become alternate correctness paths.

Region-to-Region TerraBase replication also uses direct QUIC with mutual TLS.
TerraBase owns flow control, batching, acknowledgements, causal reconciliation,
anti-entropy, and Merkle repair.

## NATS

NATS is the mandatory Orchestrator v2 consensus, control-state, discovery, and
durable-work system. Global and regional JetStream domains form one
gateway-connected supercluster without a WAN Raft group.
It never carries database documents, WAL, CRDT deltas, replication frames,
query results, reactive sync, or authoritative usage.

NATS remains absent from TerraBase correctness and customer data paths. The
checked-in v1 subjects and the adapter's composition-time global topology are
implementation state that must migrate to the accepted `ts.orch.v2` contract.

## Tenant isolation and capacity

Every database path enforces native scope:

```text
TenantId
ProjectId
DatabaseId
EnvironmentId
```

Collection prefixes are not isolation. Query, index, WAL, replication, backup,
restore, sync, administration, snapshots, and metrics all validate the same
scope.

Database API and TerraBase enforce admission before autoscaling. Bounded queues,
fair scheduling, resource budgets, backpressure, spill where safe, load
shedding, and checkpoint or snapshot fallback protect shared hosts. Capacity
signals then allow Orchestrator to add or move eligible workloads.

## Trust

Workload identity uses short-lived X.509 certificates, mutual TLS, scoped
authorization, rotated trust bundles, and auditable bootstrap grants. Same-host
communication does not weaken identity or encryption.

Secrets and customer content never enter Git, NATS, desired state, logs,
traces, metrics, fixtures, or receipts. Configuration carries secret
references, not secret bytes.

## Delivery

Build once and deploy the exact qualified digest. Release, configuration,
schema, migration, trust, rollback, and evidence identities bind to one
candidate. Each Region builds full green capacity beside unchanged blue and
keeps green outside production routing until startup, minimum health, real
dependency, authorization, isolation, routing, customer-journey, and rollback
tests pass. One durable routing generation cuts traffic over. A failed green
generation changes only green. Blue remains available through the rollback
window. Rollback restores retained qualified bytes and never rebuilds an
artifact.

TerraBase implements the invariant with surge Members, catch-up, causal and
materialized Merkle verification, and TerraBase-accepted overlapping
membership. Controllers and NATS replace one replica at a time and restore
full quorum before the next replacement. Regional blue-green does not create a
second writable TerraBase cluster or a competing control quorum.

## Production repository boundary

The production project contains no embedded development host, `dev` runtime
mode, local product composition, development NATS bootstrap, development PKI,
fixed lab routing, development-host-specific fixture, or fake-provider runtime
registration. Generic fakes and process fixtures live only in test or tooling
projects and cannot enter the production dependency graph or artifact.

## Evidence boundary

Pure tests and an external RF=1 lab cannot prove production RF=2 durability,
host loss, remote mutual TLS, cloud storage, systemd, twenty-Region behavior,
or measured noisy-neighbor isolation. Only exact candidate-bound evidence from
the owning runtime and benchmark authority can support those claims.

Historical ADRs that require permanent TerraBase R3, Project-owned Regions,
UDS TBEP, NATS inside TerraBase correctness, standalone Authentication,
Payments, Platform, or MCP are superseded for future work.
