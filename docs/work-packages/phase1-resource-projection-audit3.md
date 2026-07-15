# Phase 1 resource projection audit 3

## Goal

Close the draft read-only role-descriptor projection collision that discarded the exact owner-selected metrics, regional-telemetry, or VPN implementation.

## Allowed paths

- `tools/TerraScale.Orchestrator.SchemaGenerator/SchemaArtifacts.cs`
- `schemas/v1/role-descriptor.schema.json`
- `tests/TerraScale.Orchestrator.ContractTests/GeneratedSchemaTests.cs`
- `docs/work-packages/phase1-resource-projection-audit3.md`
- `docs/work-packages/handoffs/phase1-resource-projection-audit3.md`

## Contract

The generated read-only descriptor role is the same closed admitted-role shape without a redundant nested API version. Metrics-store, regional-telemetry-agent, and VPN-coordination-relay roles require their exact implementation domain and catalog-entry identifier. Ordinary roles forbid implementation provenance, and all roles reject unknown kinds and fields.

## Compatibility boundary

This is a breaking correction only to a draft internal read-only documentation projection whose serialization was explicitly not frozen. It does not change C# resource contracts, enum names or numerics, the standalone admitted-role artifact, a runtime wire format, manifest admission, or production behavior.
