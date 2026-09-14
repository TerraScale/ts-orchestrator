# TerraScale Orchestrator

`ts-orchestrator` is TerraScale's C# control plane, targeting .NET 11. It
reconciles the OCI estate, coordinates regional capacity and TerraBase
placement, manages admitted service runtimes, and carries durable control
state over NATS. It is an infrastructure control service; customer documents,
replication, queries, and reactive delivery remain outside this process.

The current source is in `src/TerraScale.Orchestrator`. Product scope is set by
the workspace-level `GOAL.md` when that file is present alongside this
repository. This repository's implementation map is [DESIGN.md](DESIGN.md),
and its terminology is [CONTEXT.md](CONTEXT.md).

## Ownership boundary

The control plane contains the following responsibilities:

- OCI provider models, ownership checks, compute, storage, networking,
  snapshots, and reconciliation;
- regional and global NATS topology, membership, directory publication,
  monitoring, JetStream journals, and signed control messages;
- TerraBase placement, lifecycle, recovery, and bounded control observations;
- admitted runtime roles, canonical systemd and OCI execution plans, resource
  limits, and allocation lifecycle;
- signed delivery handoffs, direct delivery, Forgejo source and CI processing,
  candidate evidence, artifact attestations, and native GitOps handoffs; and
- bootstrap grants, command identities, credential separation, telemetry, and
  operator status queries.

The process does not become a customer data proxy or a replacement for
TerraBase's database and replication authorities. Provider and runtime actions
are admitted from canonical plans and fail closed when identity, ownership,
authority, or evidence does not match.

## Runtime shape

The `TerraScale.Orchestrator` project is the main executable. Its composition
root starts regional control first, then conditionally starts global authority,
global directory, delivery, CI, native GitOps, and telemetry components when
their configuration is complete. Global authority and directory service are
GRU-only; regional control can remain available when optional global control is
unavailable.

The runtime exposes these top-level commands:

- `run` (the default) starts the configured control runtime;
- `check` validates startup composition without running the long-lived service;
- `catalog` prints the closed admitted-role catalog;
- `provision-journal` provisions regional durable journal topology; and
- `journal-writer` starts the isolated authoritative journal writer.

The `terrascale-orchestrator` executable provides the read-only `operator
status` and `operator members` queries alongside repository validation and
evidence commands. The runtime publishes as a self-contained single file for
`linux-arm64` and `linux-x64`.

Admitted roles select either a native systemd plan or an OCI plan. Every plan
contains a lowercase allocation identifier, a lowercase SHA-256 artifact
digest, architecture, bounded resources, and a canonical plan fingerprint.
Systemd plans use hardened units and encrypted workload credentials. OCI plans
use the fixed `terrascale` containerd namespace, digest-pinned images,
unprivileged execution, dropped capabilities, read-only roots, seccomp, and
cgroup-v2 limits.

## Development commands

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

- `run` and `check` use the closed `ts.orch.v2` global and regional subjects;
  signed commands, journal RPCs, query responses, startup observations, and
  delivery events use their bounded v2 envelopes;
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
6. keeps NATS resources inside the mandatory `ts.orch.v2` global and regional
   control domains without putting NATS in TerraBase correctness; and
7. preserves the completed removal of the production `Development/` namespace
   and proves that `dev` runtime modes, local product composition, development
   NATS/PKI, fixed lab routes, and fake-provider runtime registrations cannot
   re-enter production artifacts.

Until a migration item lands, current commands describe current code only. New
features and documentation must target the accepted architecture.

## Baseline validation

```bash
dotnet restore TerraScale.Orchestrator.slnx --locked-mode
dotnet build TerraScale.Orchestrator.slnx --configuration Release --nologo
dotnet test TerraScale.Orchestrator.slnx --configuration Release --no-build
```

To inspect a runtime plan or the admitted catalog without external services:

```bash
dotnet run --project src/TerraScale.Orchestrator -- catalog
dotnet run --project src/TerraScale.Orchestrator -- runtime plan \
  --role orchestrator --allocation local --digest <64-lowercase-hex-digest>
```

The long-lived `run` command requires a TLS NATS endpoint, private NKey seed,
and complete mTLS material. Optional global, directory, delivery, and CI
configuration is rejected when its authority or credential boundary is
incomplete. See [the documentation index](docs/README.md) for operational and
contract documents.

## Historical records

[Architecture decisions](docs/adr/README.md) and dated files under
`docs/evidence/` preserve safety decisions and qualification evidence from
earlier implementation stages. They remain available for traceability; the
current C# project and namespace layout in [DESIGN.md](DESIGN.md) is the source
map for this checkout.

## Documentation

- [Documentation index](docs/README.md)
- [Architecture boundaries](docs/guides/architecture-boundaries.md)
- [Production readiness](docs/guides/production-readiness.md)
- [Current implementation map](DESIGN.md)
- [Current terminology](CONTEXT.md)
