# Phase 1 provider create-observation audit 4

## Goal

Close the provider create-absence and resolved-observation replay path across regional authority scopes.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Providers/ProviderModels.cs`
- `src/TerraScale.Orchestrator.ControlPlane/Providers/ProviderOwnershipEngine.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/ProviderFourthAuditRegressionTests.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/ProviderOwnershipTests.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/ProviderOwnershipCompletenessPropertyTests.cs`
- `docs/work-packages/phase1-provider-create-observation-audit4.md`
- `docs/work-packages/handoffs/phase1-provider-create-observation-audit4.md`

## Contract

Every provider create observation carries an exact cell and compartment. Authorization accepts an absent or resolved create observation only when that scope matches the operation context before generation and state can pass. Conflicting same-key observations remain ambiguous and fail closed. A resolved-create observation intent retains the exact observation-scope references.

## Compatibility

Requiring cell and compartment is an intentional breaking constructor correction within the draft pure provider contract. Decision codes, numerics, ordering, precedence, operation-context fingerprints, and action behavior do not change.

## Boundary

This is pure deterministic evidence-scope policy. It performs no provider call, cloud mutation, network, filesystem, process, VM, deployment, or external side effect.
