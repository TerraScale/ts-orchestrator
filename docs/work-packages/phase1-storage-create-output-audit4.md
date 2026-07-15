# Phase 1 storage create output audit 4

## Goal

Close the proven accepted-output collision where Storage validated creation and mount policy but discarded the encryption-key reference, placement, storage domain, and mount purpose from its intent subject.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Storage/StorageVolumeRecord.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/StorageFourthAuditRegressionTests.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/StoragePlannerPropertyTests.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/StoragePlannerReplayCorpus.cs`
- `docs/work-packages/phase1-storage-create-output-audit4.md`
- `docs/work-packages/handoffs/phase1-storage-create-output-audit4.md`

## Contract

Every decision produced from a validated `StorageVolumeRecord` trace retains its exact immutable storage domain, encryption-key reference, placement, and mount purpose in the internal-only `StorageIntentScope`. Existing subject fields, actions, targets, codes, numeric values, validation, precedence, and planner behavior remain unchanged. The existing immutable record-copy routes remain the only non-planner copies; no public constructor, setter, deconstructor, or new factory is added.

## Boundary

These values are accepted in-memory policy provenance. Retention does not authenticate a key reference, authorize KMS use, prove encryption at rest, qualify a provider placement, execute a mount, verify a filesystem, or prove TerraBase/storage behavior. This work performs no filesystem, block-device, database, provider, network, signing, registry, VM, cloud, deployment, or CI-dispatch operation.
