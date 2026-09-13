# TerraScale Orchestrator

`ts-orchestrator` is TerraScale's C# control plane, targeting .NET 10. It
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

The separate `TerraScale.Orchestrator.CLI` executable provides the read-only
`operator status` and `operator members` queries. The
`TerraScale.Orchestrator.Tooling` executable provides repository validation and
evidence commands. Both runtime executables publish as self-contained single
files for `linux-arm64` and `linux-x64`.

Admitted roles select either a native systemd plan or an OCI plan. Every plan
contains a lowercase allocation identifier, a lowercase SHA-256 artifact
digest, architecture, bounded resources, and a canonical plan fingerprint.
Systemd plans use hardened units and encrypted workload credentials. OCI plans
use the fixed `terrascale` containerd namespace, digest-pinned images,
unprivileged execution, dropped capabilities, read-only roots, seccomp, and
cgroup-v2 limits.

## Development commands

The repository uses the SDK pinned by [global.json](global.json) and the
solution [TerraScale.Orchestrator.slnx](TerraScale.Orchestrator.slnx):

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
