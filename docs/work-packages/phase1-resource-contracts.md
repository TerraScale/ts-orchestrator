# Phase 1 resource contracts

## Goal

Implement the draft, provider-neutral common resource metadata and closed admitted-role model described at `ORCHESTRATOR.md:393-449`. This tranche does not freeze serialization or select unresolved runtime/observability/VPN implementations.

## Allowed paths

- `src/TerraScale.Orchestrator.Contracts/Resources/**`
- `tests/TerraScale.Orchestrator.ModelTests/**` except the project file and lock file
- `docs/work-packages/handoffs/phase1-resource-contracts.md`

## Required behavior

- Strong, bounded, canonical value objects for API version, stable resource ID, generation, resource version, ownership, creation actor, and audit correlation ID. Default values are invalid.
- Immutable common resource metadata with explicit validation and no silent defaults.
- A closed version-1 admitted-role discriminated catalog covering only the abstract first-party roles named in the document. Unresolved concrete metrics/VPN/runtime selections remain required descriptor inputs, not enum choices or defaults.
- Role descriptors expose only typed allowed runtimes, ports, capabilities, volume purposes, secret-profile references, health contracts, placement constraints, scaling-controller ownership, and resource bounds. No arbitrary executable, image pull tag, host path, unit text, privileged flag, Linux capability string, or NATS permission is representable.
- Defensive collection copying, duplicate rejection, stable ordering, deterministic structural equality/digest input projection, and fail-closed unknown enum/version behavior.
- Tests must prove every admitted role, every rejected unknown/default value, collection mutation isolation, duplicate handling, absence of dangerous fields/types, and deterministic output.

## Verification

`dotnet test tests/TerraScale.Orchestrator.ModelTests/TerraScale.Orchestrator.ModelTests.csproj`
