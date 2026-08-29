# TerraScale.Orchestrator

TerraScale.Orchestrator is TerraScale's production control plane and
infrastructure owner. It schedules trusted product workloads and tenant
compute, manages Regions and hosts, admits immutable releases, and orchestrates
TerraBase placement and repair.

The current architecture is defined in
[`docs/architecture/orchestrator.md`](docs/architecture/orchestrator.md) and the
workspace [`GOAL.md`](../GOAL.md). Older phase records document implemented
contracts and evidence. They do not override the current architecture.

## Product boundary

Orchestrator owns:

- Region and host lifecycle;
- workload placement, isolation, and capacity admission;
- TerraBase Member and replica identity allocation;
- certificates, workload identities, trust bundles, and rotation;
- customer database placement intent;
- repair and rebalance orchestration;
- Dashboard and Database API global deployment;
- immutable delivery, admission, promotion, and rollback; and
- cloud, storage-provider, and internal observability infrastructure.

Orchestrator does not own:

- database mutations, merge semantics, replication, anti-entropy, reactive
  sync, or authoritative usage accounting;
- Better Auth, Organizations, Projects, Users, Payments, entitlements, or MCP
  product policy;
- public SDK behavior; or
- a data-plane proxy for customer queries and writes.

The active product roles are:

| Role | Owner and runtime |
| --- | --- |
| Dashboard | One full-stack Vinext TypeScript application. It owns Better Auth, Organizations, Projects, Users, Payments, Streamable HTTP MCP, and customer workflows. |
| Database API | `TerraScale.Database`, an independent C#/.NET 10 ASP.NET Core service and the sole TBEP gateway. |
| Database engine | TerraBaseV2, the private Rust engine. |
| Orchestrator | Infrastructure, scheduling, workload identity, placement intent, repair orchestration, and delivery. |

Dashboard uses `@terrascale/sdk` and public TerraScale APIs like any customer
Project. It never connects directly to TerraBase or TBEP. Database API alone
uses generated MessagePack TBEP over QUIC with mutual TLS to TerraBase,
including on the same host.

The standalone Platform, Authentication, Payments, and `TerraScale.MCP`
services are migration sources. Direct cutover removes them after the Dashboard
replacement, import, and verification gates pass.

## TerraBase placement

A customer database selects one through twenty active Regions. GRU, SFO, and
FRA are the initial catalog. Every selected active Region stores every logical
Partition and accepts writes. Production seats two active Members per Region
and Partition across independent failure domains.

`RegionalDurable` acknowledges after both local Members durably append the
commit. It never waits for WAN replication. `GlobalDurable` acknowledges only
after every selected Region has durably accepted the commit. Backup is an
independent optional, read-only, non-voting copy.

TerraBase owns membership acceptance, native delta CRDT replication,
partition-scoped causality, anti-entropy, Merkle verification, snapshots,
compaction, reactive sync, and authoritative usage accounting. Orchestrator
supplies typed intent and capacity. It cannot appoint a data leader, primary,
owner, or permanent coordinator.

## NATS boundary

NATS is a replaceable control adapter. It may simplify accepted configuration,
discovery, durable control work, and operational event distribution. It never
carries TerraBase documents, WAL records, CRDT deltas, replication frames,
query results, client sync traffic, or usage truth. NATS availability never
decides whether a database write committed or whether replicas converged.

Existing serving Regions must continue reads, eligible writes, replication,
repair, and client reconnect recovery when Orchestrator or NATS is unavailable.
If NATS no longer meets the control plane's safety, isolation, performance, or
operational needs, replace it behind typed contracts.

## Noisy-neighbor protection

Autoscaling reacts too slowly to be the isolation boundary. Database API and
TerraBase enforce native scope, admission, and resource budgets before new
capacity arrives.

Every durable database path carries and validates:

```text
TenantId
ProjectId
DatabaseId
EnvironmentId
```

Collection-name prefixes are not tenant isolation. Query, index, replication,
backup, restore, sync, administration, snapshots, and metrics all enforce the
same native scope.

Scheduling and admission cover CPU, memory, disk, I/O, network bandwidth,
mutation rate, query cost, subscriptions, fan-out, WAL and compaction backlog,
snapshot traffic, and replication catch-up. Bounded queues, fair scheduling,
load shedding, disk spill where safe, and checkpoint or snapshot fallback stop
one tenant from consuming unbounded shared resources. Orchestrator adds or
moves capacity after sustained pressure, but admission remains safe while that
work is pending.

## Region catalog admission

A Region cannot enter the customer catalog until it has qualified:

- admitted hosts and independent failure domains;
- Dashboard and Database API instances;
- the Dashboard system Project caught up and Merkle verified;
- workload identities and rotated trust;
- public and strict routing;
- Better Auth and Database API authorization;
- TerraBase replication, anti-entropy, recovery, and RF=2 Member-loss behavior;
- observability and noisy-neighbor protection; and
- exact failure, restore, and rollback receipts.

Catalog discovery is not catalog admission. Publication requires policy and
explicit owner approval until the owner accepts an automated publication
rule. Region removal fences routing, drains sessions, fulfills retention and
deletion obligations, retires replica actors, and records receipts.

## Current implementation boundary

The checked-in executable still implements earlier NATS-native control-plane
contracts and a closed legacy workload catalog. That is implementation state,
not permission to retain the old product architecture.

Current facts:

- `run` and `check` require JetStream-enabled NATS because their adapters have
  not yet been replaced or made optional;
- regional and global control journals, discovery, delivery, and native GitOps
  currently use typed NATS resources;
- some typed policies and tests still model an R3 control journal and the old
  first-party roles;
- local development wiring still reflects the previous service set; and
- the repository has no production deployment authority until its exact
  qualification gates pass.

Migration work must preserve durable control history and fail closed while it:

1. changes product roles to Dashboard, Database API, and TerraBaseV2;
2. moves database placement from Project inheritance to database-owned Region
   selection;
3. changes TerraBase production placement to RF=2 per selected Region;
4. removes UDS and HTTP engine paths in favor of QUIC TBEP with mutual TLS;
5. removes the standalone Authentication, Payments, Platform, and MCP roles;
6. makes NATS optional and replaceable where it provides no net benefit; and
7. updates DevHost, delivery manifests, routes, credentials, SDK contracts,
   tests, and receipts as one cutover.

Until a migration item lands, current commands describe current code only. New
features and documentation must target the accepted architecture.

## Baseline validation

```bash
dotnet restore TerraScale.Orchestrator.slnx --locked-mode --disable-parallel
dotnet build TerraScale.Orchestrator.slnx --no-restore --maxcpucount:1
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- test
```

The exact-tree `development-attest` command builds once, runs the five TUnit
executables sequentially with at most four active tests per module, and then
runs policy tooling. A repository-wide lease prevents overlap with the Podman
lab. The run must stay under the 20 GiB owned-process ceiling so the 24 GiB
development host retains 4 GiB for the operating system and tools.

```bash
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- adr-readiness
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- owner-decisions
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- test
```

Run the tooling executable without arguments for the full command inventory.

## Running the current adapter

These commands exercise the current NATS adapter. They do not define the final
product boundary.

```bash
TS_ORCH_CELL=gru \
TS_ORCH_NATS_URL=nats://127.0.0.1:4222 \
TS_ORCH_REPLICAS=1 \
dotnet run --project src/TerraScale.Orchestrator -- check

TS_ORCH_CELL=gru \
TS_ORCH_NATS_URL=tls://control-nats-gru.internal:4222 \
TS_ORCH_REPLICAS=3 \
TS_ORCH_NATS_NKEY_FILE=/run/credentials/terrascale/controller.nk \
TS_ORCH_NATS_TLS_CA_FILE=/run/credentials/terrascale/ca.pem \
TS_ORCH_NATS_TLS_CERT_FILE=/run/credentials/terrascale/controller.pem \
TS_ORCH_NATS_TLS_KEY_FILE=/run/credentials/terrascale/controller-key.pem \
dotnet run --project src/TerraScale.Orchestrator -- run
```

Remote NATS connections require TLS, scoped NKey or credentials files, and
complete mutual TLS identity. Credential files must be owner-private. Never
pass raw secret material on the command line or record it in logs, traces,
metrics, NATS, fixtures, or receipts.

The current adapter supports Infisical Universal Auth for secret references.
Explicit typed configuration wins over fetched configuration. The runtime
materializes file-valued secrets into owner-private temporary files and removes
them on shutdown. Plain HTTP is allowed only for a loopback development
Infisical endpoint.

## DevHost topology

The development lab remains one always-on GRU/SFO/FRA topology at RF=1.
Profile switches and reduced topologies are forbidden. RF=1 proves routing,
causal catch-up, and convergence. It cannot prove production RF=2 durability or
Member-loss behavior.

Dashboard keeps fixed tailnet HTTPS port `18446`. The legacy Authentication
route remains on `18445` only until Better Auth cutover. Database API needs a
fixed tailnet and loopback route chosen after collision checks and owner
approval, then recorded atomically in DevHost, Orchestrator, SDKs, and public
documentation. Do not use an unapproved floating port.

## Validation limits

Pure tests and the local lab do not prove:

- production systemd, containerd, cloud, or provider storage;
- remote mutual TLS and certificate rotation;
- RF=2 local durability and host-loss recovery;
- native TerraBase replication or reactive sync under production load;
- twenty-Region full-mesh behavior;
- noisy-neighbor isolation at measured density;
- direct Auth, Payments, and MCP cutover; or
- public launch readiness.

Production claims require exact candidate-bound evidence from the owning
runtime and the benchmark authority.

## Documentation map

- [Current architecture](docs/architecture/orchestrator.md)
- [Documentation index](docs/README.md)
- [Architecture boundaries](docs/guides/architecture-boundaries.md)
- [Direct delivery runbook](docs/runbooks/direct-delivery.md)
- [Historical phase contract record](docs/guides/phase1-contracts.md)
- [Historical owner decisions](docs/decisions/README.md)

Historical ADRs, phase records, and evidence remain immutable context unless a
correction notice says otherwise. A current design must not cite them as
authority when they conflict with the workspace `GOAL.md` or the current
architecture document.
