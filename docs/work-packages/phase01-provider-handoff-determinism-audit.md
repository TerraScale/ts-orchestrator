# Phase 0/1 provider handoff determinism audit

## Goal

Close the proven pure-output gap where equivalent verified greenfield Pulumi handoff inventories authorized regional self-management but retained caller-dependent enumeration order in the accepted adapter intent.

## Requirement mapping

- `REQ-O010`: exact ownership/handoff receipt and regional ownership boundary.
- `INV-014`: concrete regional resources transfer to the regional orchestrator only after the signed handoff.
- Hard pre-deployment L0 gate: deterministic replay/permutation and greenfield Pulumi handoff behavior must be covered before any adapter receives mutation authority.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Providers/ProviderModels.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/CompletionGapAudit2CounterexampleTests.cs`
- `docs/work-packages/phase01-provider-handoff-determinism-audit.md`
- `docs/work-packages/handoffs/phase01-provider-handoff-determinism-audit.md`

## Contract

`FreshBootstrapInventory` defensively copies and canonically orders each Expected, Pulumi, and Regional sequence by provider resource identity using ordinal comparison, then resource kind, then generation. The same exact inventory-item objects are retained. Bounds, input exceptions, duplicate detection, inventory fingerprints, proof validation, decision trace and precedence, public signatures, and accepted or held outcomes do not change.

## Boundary

This is a pure in-memory snapshot/output correction. It does not sign a handoff, run Pulumi, adopt or mutate a resource, call a provider, start NATS, create a VM, choose an owner option or provider policy, or provide L0/L3S/L4 acceptance evidence.
