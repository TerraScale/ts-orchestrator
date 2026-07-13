# Phase 1 desired/observed reconciliation core

## Goal

Implement a pure deterministic desired/observed state engine and dependency planner for Phase 1. It emits typed adapter intents only and owns no domain-specific mutation policy.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Reconciliation/**`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Reconciliation*.cs`
- `docs/work-packages/handoffs/phase1-reconciliation-core.md`

## Required behavior

- Immutable bounded resource identity, kind, desired generation/digest/dependencies, observation generation/digest/freshness identity, and explicit caller policy.
- Validate unique resources, closed caller-supplied kind catalog, dependency existence, no self-edge/cycle, generation monotonicity, and exact identity pairing.
- Produce a deterministic topological plan independent of input order. A resource is converged only on exact desired generation/digest; stale/missing observations emit Observe, and eligible drift emits Reconcile intent only after dependencies converge.
- A newer-than-desired or conflicting same-generation observation holds fail-closed. Failed/held dependencies propagate a typed hold without hiding the root reason.
- Intents contain identity/generation/digest/dependency proof only; no callbacks, arbitrary payloads, executable data, or infrastructure behavior.
- Complete stable reason trace, defensive copies, duplicate/permutation/cycle/missing/stale/future/conflict tests, 10k-resource deterministic benchmark-style test, and no mutation of inputs.
- No wall clock, NATS, files, provider/runtime choices, retries, or domain policy defaults.

## Verification

`dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj`
