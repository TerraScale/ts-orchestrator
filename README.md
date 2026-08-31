# TerraScale.Orchestrator

TerraScale.Orchestrator is TerraScale's production control plane and
infrastructure owner. It schedules trusted product workloads and tenant
compute, manages Regions and hosts, admits immutable releases, and orchestrates
TerraBase placement and repair.

The current architecture is defined in the repository
[`GOAL.md`](GOAL.md), [ADR 0033](docs/adr/0033-gru-global-authority-and-regional-autonomy.md),
and the workspace [`GOAL.md`](../GOAL.md). Older phase records document
implemented contracts and evidence. They do not override the current goal.

## Product boundary

Orchestrator owns:

- Region and host lifecycle;
- workload placement, isolation, and capacity admission;
- TerraBase Member and replica identity allocation;
- certificates, workload identities, trust bundles, and rotation;
- customer database placement intent;
- repair and rebalance orchestration;
- Dashboard and Database API global deployment;
- immutable regional blue-green delivery, admission, promotion, and rollback;
  and
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
| Database API | An independently deployable C#/.NET 10 ASP.NET Core service and the sole TBEP gateway. Its permanent source home is `TerraScale.Internals`; the standalone `TerraScale.Database` repository retires after migration receipts pass. |
| Database engine | TerraBase, the private Rust engine. |
| Orchestrator | Infrastructure, scheduling, workload identity, placement intent, repair orchestration, and delivery. |

Dashboard uses `@terrascale/sdk` and public TerraScale APIs like any customer
Project. It never connects directly to TerraBase or TBEP. Database API alone
uses generated FlatBuffers TBEP over QUIC with mutual TLS to TerraBase,
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

NATS JetStream R3 is the selected Orchestrator consensus and authoritative
control-state system. Regional domains form a gateway-connected supercluster
and continue safe work during GRU loss. NATS never
carries TerraBase documents, WAL records, CRDT deltas, replication frames,
query results, client sync traffic, or usage truth. NATS availability never
decides whether a database write committed or whether replicas converged.

Existing serving Regions must continue reads, eligible writes, replication,
repair, and client reconnect recovery when Orchestrator or NATS is unavailable.
Replacing NATS requires a new goal and ADR. It cannot become part of TerraBase
correctness or a customer request path.

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

- `run` and `check` use the earlier NATS adapter and have not migrated to the
  accepted `ts.orch.v2` global and regional domains;
- regional and global control journals, discovery, delivery, and native GitOps
  currently use typed NATS resources;
- some typed policies and tests still model an R3 control journal and the old
  first-party roles;
- commit `4309019` removed the legacy production `Development/` composition,
  local product supervision, development NATS and PKI, and their
  production-referenced tests; repository-purity scans still need release
  evidence; and
- the repository has no production deployment authority until its exact
  qualification gates pass.

Migration work must preserve durable control history and fail closed while it:

1. changes product roles to Dashboard, Database API, and TerraBase;
2. moves database placement from Project inheritance to database-owned Region
   selection;
3. changes TerraBase production placement to RF=2 per selected Region;
4. removes UDS and HTTP engine paths in favor of QUIC TBEP with mutual TLS;
5. removes the standalone Authentication, Payments, Platform, and MCP roles;
6. migrates v1 NATS resources to the mandatory `ts.orch.v2` global and regional
   control domains without putting NATS in TerraBase correctness; and
7. preserves the completed removal of the production `Development/` namespace
   and proves that `dev` runtime modes, local product composition, development
   NATS/PKI, fixed lab routes, and fake-provider runtime registrations cannot
   re-enter production artifacts.

Until a migration item lands, current commands describe current code only. New
features and documentation must target the accepted architecture.

## Baseline validation

```bash
go mod download
go build ./...
go vet ./...
go test ./...
go test -race ./...
```

The repository tooling is a Go command. Run it with, for example:

```bash
go run ./tools/orchestrator-tooling adr-readiness
go run ./tools/orchestrator-tooling owner-decisions
go run ./tools/orchestrator-tooling test
```

Run the tooling executable without arguments for the full command inventory.

## Running the current adapter

These commands exercise the current NATS adapter. They do not define the final
product boundary.

```bash
TS_ORCH_CELL=gru \
TS_ORCH_NATS_URL=nats://127.0.0.1:4222 \
TS_ORCH_REPLICAS=1 \
go run ./cmd/orchestrator check

TS_ORCH_CELL=gru \
TS_ORCH_NATS_URL=tls://control-nats-gru.internal:4222 \
TS_ORCH_REPLICAS=3 \
TS_ORCH_NATS_NKEY_FILE=/run/credentials/terrascale/controller.nk \
TS_ORCH_NATS_TLS_CA_FILE=/run/credentials/terrascale/ca.pem \
TS_ORCH_NATS_TLS_CERT_FILE=/run/credentials/terrascale/controller.pem \
TS_ORCH_NATS_TLS_KEY_FILE=/run/credentials/terrascale/controller-key.pem \
go run ./cmd/orchestrator run
```

Remote NATS connections require TLS, scoped NKey or credentials files, and
complete mutual TLS identity. Credential files must be owner-private. Never
pass raw secret material on the command line or record it in logs, traces,
metrics, NATS, fixtures, or receipts.

The current adapter supports Infisical Universal Auth for secret references.
Explicit typed configuration wins over fetched configuration. The runtime
materializes file-valued secrets into owner-private temporary files and removes
them on shutdown. Production secret retrieval uses authenticated TLS. A
development-only transport or secret default is not part of the target runtime.

## Production repository boundary

The target production solution and artifact contain no embedded development
host, `dev` runtime mode, local product composition, development NATS bootstrap,
development PKI or credentials, fixed lab route, local Podman supervisor,
development-host-specific fixture, or fake-provider runtime registration. Generic fakes
and process fixtures may exist only in test or tooling projects with no
production reference. The current legacy implementation is migration debt, not
a supported Orchestrator feature.

Production releases use regional blue-green. Each Region starts a complete
green generation beside unchanged blue, runs minimum-health, dependency,
authorization, isolation, routing, synthetic customer-journey, and rollback
tests, then switches traffic through one durable routing generation. Failure
before cutover removes only green. Blue remains available through the rollback
window. TerraBase applies the same replacement-before-removal invariant through
surge Members and accepted membership, not a second writable cluster.

## Validation limits

Pure tests and test-owned fixtures do not prove:

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

- [Production goal](GOAL.md)
- [Accepted authority ADR](docs/adr/0033-gru-global-authority-and-regional-autonomy.md)
- [Documentation index](docs/README.md)
- [Architecture boundaries](docs/guides/architecture-boundaries.md)

Git history retains the deleted superseded ADRs, phase records, and evidence.
