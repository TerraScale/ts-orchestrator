# Phase 1 delivery stage output audit 4

## Goal

Close the proven accepted-output collision where initial staging discarded the validated release strategy, rollback policy, ordered-cell policy, and selected cell-availability evidence.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Delivery/DeliveryContracts.cs`
- `src/TerraScale.Orchestrator.ControlPlane/Delivery/DeliveryEngine.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/DeliveryFourthAuditRegressionTests.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/DeliveryPolicyCompletenessPropertyTests.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/DeliveryStageFingerprint.cs`
- `docs/work-packages/phase1-delivery-stage-output-audit4.md`
- `docs/work-packages/handoffs/phase1-delivery-stage-output-audit4.md`

## Contract

An accepted initial `StageReleaseIntent` retains the exact validated `ReleaseSpec` and exact selected `CellArtifactAvailability`. Existing release, operation, cell, generation, forward artifact, rollback artifact, digest, signing, signature, and architecture projections remain and derive only from those retained inputs. Denied decisions retain only the hold intent. Error numerics, trace order, rollout decisions, validation, precedence, advance behavior, and rollback behavior do not change.

## Boundary

The retained strategy, rollback policy, and ordered cells are caller policy provenance. Retention does not claim that this decision engine has executed, qualified, or externally enforced a canary, rolling, blue-green, or ordered-stateful rollout. The selected availability is accepted in-memory evidence, not proof of registry contents, signature authenticity, deployment success, or runtime health. This work adds no wire schema and performs no process, network, signing, registry, VM, cloud, credential, filesystem deployment, or CI-dispatch operation.
