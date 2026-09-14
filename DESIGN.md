# TerraScale.Orchestrator design

Status: current C# implementation map. Product decisions remain owned by the
workspace-level `GOAL.md` when that file is present alongside this repository.
This document describes source that exists in this checkout and does not
preserve retired source layouts or command wrappers.

## Build and project layout

The solution is `TerraScale.Orchestrator.slnx`. The SDK is pinned in
`global.json` to .NET SDK 11.0.100-rc.1.26425.128. `Directory.Build.props` applies `net11.0`,
nullable reference types, implicit usings, preview language features,
warnings-as-errors, latest analysis and code-style checks, deterministic builds,
and locked package restore to every project.

| Project | Role | Output |
| --- | --- | --- |
| `src/TerraScale.Orchestrator/TerraScale.Orchestrator.csproj` | Runtime, control plane, provider adapters, delivery, messaging, host runtime planning, and repository validation tooling | `terrascale-orchestrator`; self-contained single file for `linux-arm64` and `linux-x64` |
| `tests/TerraScale.Orchestrator.ControlPlane.Tests` | Control-plane engines, providers, journals, runtime, security, and integration contracts | TUnit executable |
| `tests/TerraScale.Orchestrator.ModelTests` | Model and simulation coverage | TUnit executable |
| `tests/TerraScale.Orchestrator.Protocol.Tests` | Protocol, subject grammar, envelopes, and fuzz corpus | TUnit executable |
| `tests/TerraScale.Orchestrator.Scheduler.Tests` | Deterministic scheduler and availability policy coverage | TUnit executable |
| `tests/TerraScale.Orchestrator.Tests` | Runtime composition, delivery, membership, and operator boundaries | TUnit executable |
| `tests/TerraScale.Orchestrator.ControlPlane.JournalChild` | Child process used by journal lifecycle tests | Test fixture executable |

Package versions are centrally managed in `Directory.Packages.props`. The
runtime uses `NATS.Net`, `OCI.DotNetSDK.Core`, `OpenTelemetry.Exporter.OpenTelemetryProtocol`,
and `ZString`; test projects use TUnit where their project file requires it.

## Namespace map

The runtime project is feature-sliced. Keep a responsibility's contracts,
decision logic, and adapters in its existing namespace rather than creating a
second compatibility layer.

| Namespace or directory | Responsibility |
| --- | --- |
| `Bootstrap` | Signed bootstrap grants, trust bundles, canonical payloads, and replay journals |
| `Contracts` | Command identifiers, contract versions, stable identifiers, resource descriptors, and the admitted role catalog inputs |
| `Protocol` | Versioned envelopes, signed command material, subject grammar, capability policy, durable work inventory, and delivery semantics; `protocol-manifest.json` is embedded in the runtime assembly |
| `ControlPlane.Authority` | Fenced authority terms, leases, digests, and mutation decisions |
| `ControlPlane.Budgets` | Resource budgets, evidence, anomalies, and admission decisions |
| `ControlPlane.Compute`, `Storage`, `Networking` | OCI compute, volume lifecycle, network discovery, and route decisions |
| `ControlPlane.Providers` | OCI models, ownership checks, create-node handoffs, volume expansion, and CI runner capacity |
| `ControlPlane.Reconciliation` | Desired-state reconciliation and provider observation boundaries |
| `ControlPlane.DatabasePlacement`, `ControlPlane.TerraBase` | TerraBase placement intent, lifecycle, recovery, and bounded member coordination |
| `ControlPlane.Runtime` | Runtime assignment, lifecycle decisions, NATS lifecycle journals, authority gates, and the native systemd executor |
| `ControlPlane.Delivery` | Delivery contracts, endpoint verification, direct delivery, and delivery decisions |
| `ControlPlane.Evidence`, `ControlPlane.Observability`, `ControlPlane.Security`, `ControlPlane.Snapshots`, `ControlPlane.Operations` | Evidence gates, telemetry projections, security decisions, signed snapshots, operation journals, and operation recovery |
| `Messaging` | Regional and global NATS runtimes, membership, directory, topology, gateways, monitoring, credentials, and journal services |
| `Delivery` | Forgejo ingestion, CI runner execution and isolation, candidate handoffs, artifact attestations, native GitOps, and command identities |
| `Runtime` | Closed admitted-role catalog, canonical systemd and OCI plans, host runtime adapters, and MCP workload handling |
| `Scheduling` | Deterministic scheduling and availability policy evaluation |
| `Security` | Infisical integration and system-project bootstrap verification |
| `Observability` | OpenTelemetry runtime instrumentation |
| `Operations` | Read-only operator status and membership queries |

The project graph has one production runtime assembly. Test projects reference
the runtime project and keep their test-only fixtures in their own project
directories. Repository validation commands are feature-sliced under the
runtime project and use the same executable entry point.

## Composition and state boundaries

`Program.cs` is the runtime composition root. `OrchestratorOptions` parses the
command and `TS_ORCH_*` environment, validates cell and replica bounds, and
requires role-appropriate NATS identities. `OrchestratorRuntimeComposition`
then selects regional control, optional global authority and directory, direct
delivery, CI consumption, native GitOps, and telemetry. Global authority and
the global directory service are admitted only in GRU. Forgejo ingestion and
CI require global authority plus an OCI runner pool; incomplete optional
configuration fails at startup.

`Messaging` owns NATS client and JetStream boundaries. Regional control uses a
scoped NKey and mTLS identity. Global authority, directory, infrastructure,
and authoritative journal writer identities are distinct roles. The protocol
manifest, subject taxonomy, capability matrix, durable work inventory, and
message envelopes define the wire surface.

`ControlPlane` owns pure decisions and durable operation transitions. Provider
adapters consume canonical authorization and ownership evidence before an
external mutation. Unknown or conflicting observations are held for recovery;
late completions cannot authorize a different operation. Signed snapshots,
bootstrap grants, command identities, and credential boundaries remain
separate from customer data and database replication.

`Runtime` constructs `HostRuntimePlan` values only from the closed
`AdmittedRoleCatalog`. A plan binds role, driver, allocation ID, artifact
digest, architecture, resource limits, and an execution-specific systemd or
OCI payload. The systemd adapter verifies canonical unit properties before
using `systemctl` or `systemd-run`. The containerd adapter verifies image
reference, platform, security profile, namespace, and plan fingerprint before
starting or deleting an allocation.

## Commands and validation

The main executable accepts `run` (the default), `check`, `catalog`,
`provision-journal`, and `journal-writer`. It also dispatches repository
validation commands: `adr-readiness`, `owner-decisions`, `ci-result-manifest`,
`development-attest`, `phase0-evidence`, `json-format`, `test`, and
`workspace-topology-lease-holder`. The same executable accepts `operator
status` and `operator members`.

Use the pinned SDK and solution for local verification:

```bash
dotnet restore TerraScale.Orchestrator.slnx --locked-mode
dotnet build TerraScale.Orchestrator.slnx --configuration Release --nologo
dotnet test TerraScale.Orchestrator.slnx --configuration Release --no-build
```

The runtime plan and role catalog can be inspected without connecting to a
provider:

```bash
dotnet run --project src/TerraScale.Orchestrator -- catalog
dotnet run --project src/TerraScale.Orchestrator -- runtime plan \
  --role orchestrator --allocation local --digest <64-lowercase-hex-digest>
```

## Historical records

[Architecture decisions](docs/adr/README.md) and dated evidence under
`docs/evidence/` are retained for traceability. They preserve the safety and
qualification record of earlier stages, but they are not source maps or
replacement command instructions. New implementation references should point
to the C# projects and namespaces above.
