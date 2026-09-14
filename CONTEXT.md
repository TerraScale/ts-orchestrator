# TerraScale orchestration terms

Use these names in C# namespaces, code, tests, issues, and documentation. The
workspace-level `GOAL.md`, when present alongside this repository, defines
product scope; these terms describe the implementation in this checkout.

## Control and messaging

**TerraScale Orchestrator**

The .NET 11 control service in `src/TerraScale.Orchestrator`. It validates
configuration, starts regional NATS control, optionally joins global authority
and directory services, evaluates control-plane decisions, and coordinates
provider, runtime, TerraBase, delivery, and telemetry boundaries.

**Regional control**

The NATS-backed control runtime for one cell. It owns regional membership,
regional operation requests, runtime assignments, and regional observations.
It requires a scoped controller identity and mTLS material when running.

**Global authority**

The optional GRU-only control runtime for global state, directory publication,
cross-region delivery, CI, and native GitOps. Its presence does not make a
NATS storage leader a separate application authority.

**Global directory**

The publisher and watcher runtime that exposes admitted cell membership and
bounded health observations. The directory service is configured separately
from the regional controller and is valid only with its publisher/watch
runtime.

**Control state**

Fenced, signed, idempotent orchestration intent, observations, and receipts
stored through NATS and JetStream. It does not contain customer documents,
database replication, query results, reactive frames, or usage truth.

**Operation journal**

A durable record of an operation's intent, authorization, dispatch, provider
observation, and terminal outcome. Recovery resumes the recorded operation and
does not create a replacement merely because a response was lost.

**Fail-closed composition**

Startup behavior that rejects invalid cell placement, credential ownership,
authority combinations, missing delivery executors, and incomplete TLS/NKey
configuration before a component can mutate state.

## Runtime

**Admitted role**

A role in the closed `AdmittedRoleCatalog`. The catalog binds the role to an
artifact key, allowed runtime drivers, capabilities, host placement rules,
and minimum replicas. Examples include `orchestrator`, `terrabase-member`,
`control-nats-server`, `product-nats-server`, `grafana`, and `ci-runner`.

**Allocation**

One admitted role instance identified by a DNS-style allocation ID and bound
to an artifact digest, architecture, driver, resources, and execution plan.

**Host runtime plan**

The versioned value produced by `HostRuntimePlan.Create`. It is the complete
canonical input for starting, observing, stopping, or deleting an allocation.
It contains exactly one systemd or OCI execution payload.

**Native systemd plan**

An allocation executed through a hardened systemd unit. The plan pins the
artifact path, arguments, encrypted workload credential, cgroup-v2 limits,
and systemd isolation properties. The adapter rechecks the canonical plan
before invoking fixed `systemctl` or `systemd-run` paths.

**OCI plan**

An allocation executed through containerd in the `terrascale` namespace. The
plan pins the registry image digest and platform, runs as an unprivileged UID
and GID, drops capabilities, uses a read-only root and seccomp profile, and
binds cgroup-v2 limits.

**Plan fingerprint**

The lowercase SHA-256 digest over the complete plan identity and execution
settings. An observed systemd or containerd allocation with a different
fingerprint is not owned by the requested plan and is rejected.

**MCP workload**

A workload represented by the runtime MCP manifest and contract. Its
reconciliation follows the same admitted role, allocation, identity, and
artifact rules as other runtime assignments.

## Provider, placement, and delivery

**Provider ownership**

The evidence that an OCI resource belongs to the declared operation, cell,
and compartment. Discovery or a matching tag alone cannot authorize adoption,
deletion, or compensation.

**TerraBase placement intent**

The orchestrator's bounded request for member allocation, region, capacity,
or lifecycle action. TerraBase remains authoritative for membership,
replication, and database correctness.

**Candidate handoff**

The signed delivery document consumed by the orchestrator. It binds source and
tree identity, immutable artifacts, evidence, target, and rollback material.
It grants no authority by itself; admission and durable control state are
still required.

**Direct delivery**

The authenticated delivery mutation path composed from regional or global
adapters. Run mode may serve it; check mode consumes configuration and
validation without enabling the live mutation endpoint.

**Native GitOps handoff**

A signed, journaled handoff of an admitted source and cell specification to
regional runtime state. Source identity, acceptance barriers, convergence, and
live receipts are separate from provider observations.

## Security and evidence

**Command identity**

The signing and verification material used for command envelopes and delivery
handoffs. CI job dispatch, artifact attestations, and runtime observations can
use independently configured role identities and are rejected when the
required signer or trusted verifier is missing.

**Controller identity**

The regional NATS NKey and mTLS identity used by the process for control
requests. Global, directory, infrastructure, and journal-writer identities
are separate credentials with separate admission rules.

**Evidence gate**

A bounded, verifiable set of observations required before an operation can be
authorized or promoted. Missing, stale, conflicting, or unverifiable evidence
holds the operation and cannot be replaced with a warning or retry.

**Historical record**

An ADR or dated evidence file retained for traceability. The records linked by
the [ADR index](docs/adr/README.md) preserve earlier safety decisions and
qualification evidence; the current project and namespace map remains in
[DESIGN.md](DESIGN.md).
