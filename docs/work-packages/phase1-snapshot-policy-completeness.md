# Phase 1 snapshot policy completeness

## Goal

Audit the pure signed-snapshot validator and restore planner against the snapshot/replay and anti-rollback requirements in `ORCHESTRATOR.md:538-550` and `ORCHESTRATOR.md:1120-1150`.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Snapshots/**`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Snapshot*.cs`
- `docs/work-packages/phase1-snapshot-policy-completeness.md`
- `docs/work-packages/handoffs/phase1-snapshot-policy-completeness.md`

## Required behavior

- A restore candidate must not carry a state generation lower than the current accepted generation, even when its signed stream position advances.
- Equal state generation remains valid when the signed stream position advances and every other validation gate passes; snapshots at multiple journal checkpoints may describe the same accepted state generation.
- Preserve validation precedence: scope, schema compatibility, epoch, stream position, generation, state digest, then signature outcome.
- Exercise exact plan projections, all defined and undefined dependency outcomes, every typed error catalog, invalid context fields, delegate call suppression, deterministic replay, cultures, construction closure, and overflow.

## Boundary

This package is pure decision code and tests. It performs no serialization, signing, hashing, persistence, NATS, filesystem, process, network, cloud/provider, VM, container, or deployment operation. It makes no L0, L0C, mutation-score, fuzz-budget, cryptographic, snapshot-persistence, or production-readiness claim.

## Verification

```text
dotnet restore TerraScale.Orchestrator.slnx --locked-mode
dotnet build TerraScale.Orchestrator.slnx -c Release --no-restore --nologo -warnaserror
dotnet run --project tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj -c Release --no-build --no-restore -- --treenode-filter '/*/*/Snapshot*/*' --no-progress
dotnet run --project tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj -c Release --no-build --no-restore -- --no-progress
dotnet test TerraScale.Orchestrator.slnx -c Release --no-build --no-restore -- --no-progress
git diff --check
```
