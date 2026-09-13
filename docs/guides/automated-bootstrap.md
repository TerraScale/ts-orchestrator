# Automated OCI bootstrap

Routine TerraScale estate creation is orchestrator-owned. There is no manual
OCI resource runbook. The owner completes only account, payment, home-Region,
plan, and initial credential setup, then runs the authenticated bootstrap
command from a trusted machine.

The [workspace goal](../../../GOAL.md#ts-orchestrator) defines authority and
production outcomes; this guide describes the bootstrap design.
The current C# solution exposes runtime composition and validation, but it
does not yet ship a greenfield `bootstrap` or `add-region` command. The
Firecracker qualification and bootstrap commands described by earlier Go
implementation work are historical design evidence, not executable commands
for this checkout. Run the current local validation from the repository
[README](../../README.md) before integrating a future bootstrap command.

## Owner prerequisites

- PAYG tenancy with GRU (`sa-saopaulo-1`) as the home Region.
- Initial OCI API identity scoped to the bootstrap operations.
- Cloudflare Pro and Workers Paid account prerequisites and narrowly scoped
  initial credentials.
- Grafana Cloud and required external account identifiers.
- Local release-verification material supplied as file references, never raw
  secret command-line values.

These prerequisites authorize the command; they do not become desired estate
and are not copied onto a host.

## Current runtime boundary

```bash
dotnet restore TerraScale.Orchestrator.slnx --locked-mode
dotnet build TerraScale.Orchestrator.slnx --configuration Release --nologo
dotnet test TerraScale.Orchestrator.slnx --configuration Release --no-build
```

The C# executable currently provides `run`, `check`, `catalog`,
`provision-journal`, and `journal-writer`. `check` validates startup
composition without opening a long-lived service; `run` starts the admitted
control runtime after its TLS, NKey, cell, and authority checks. Neither
command performs the greenfield OCI mutations listed below. The design
requirements for a future bootstrap implementation are:

1. created and verified compartments, IAM policy, and instance-principal
   authority;
2. created GRU networking, routing, NSGs, Vault software keys, Object Storage
   buckets, versioning, and lifecycle policy;
3. created two TerraBase member hosts in separate failure domains, using
   Ampere A1 and automatically selecting E5 amd64 when A1 capacity is
   unavailable;
4. declared two dedicated 1 OCPU/1 GiB orchestrator worker hosts per Region;
5. installed only `ts-node` through cloud-init;
6. admitted host identities and let `ts-node` fetch, verify, and run the signed
   orchestrator and TerraBase artifacts on member machines, with the
   orchestrator worker artifact reserved for the dedicated worker hosts;
7. started the first GRU master and regional orchestrator with temporary
   pre-customer R1 storage on the selected GRU member;
8. converged certificates, Cloudflare DNS and routes, KV, telemetry, and
   external probes; and
9. handed mutation authority to the running control plane and removed the
   bootstrap API key from runtime state.

The durable autoscale target currently changes TerraBase member capacity only.
Dedicated orchestrator workers remain at the declared two-host regional floor;
worker scale-out or scale-in is held until it has its own target and safe
termination proof.

Every mutation uses persisted intent, provider idempotency, re-observation,
and ownership fencing. An uncertain destructive operation is never repeated
until its outcome and authority are proven. Restarting the command resumes the
same operation rather than creating parallel estate.

## Completion

Bootstrap completes only after both GRU member hosts, storage and backup
targets, a local orchestrator on each member machine, the control replica,
identities, edge routing, telemetry, and external probes are healthy. Partial completion remains declared state for automatic
repair; it does not turn into a list of console steps.

Every added Region must eventually start its own regional orchestrator under
GRU authority, with the same reconcile, readiness, ownership, and rollback
rules. The current C# runtime has no `add-region` entry point, so SFO/FRA
admission, fenced R3 promotion, quorum verification, and bootstrap-authority
retirement remain design requirements rather than runnable procedures.

Region removal is declarative and must fence placement and routing, drain
safely, and prove all
residency and retention obligations before deletion.

The local Firecracker suite qualifies orchestration behavior and failure
handling. A real bootstrap is still required to qualify OCI and Cloudflare
service behavior, credentials, quotas, and production performance.
