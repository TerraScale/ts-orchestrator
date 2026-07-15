# Phase 1 TerraBase accepted upgrade output audit 3

## Goal

Close the proven accepted-output collision where post-apply upgrade observation and completion decisions discarded the exact validated current and target release pair.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/TerraBase/TerraBaseLifecycle.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraBaseThirdAuditRegressionTests.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/TerraBaseSecondAuditPropertyTests.cs`
- `docs/work-packages/phase1-terrabase-audit3.md`
- `docs/work-packages/handoffs/phase1-terrabase-audit3.md`

## Contract

Every non-hold upgrade decision retains the already validated `TerraBaseUpgradeIntentSubject`, including post-apply health observation and successful completion. Existing actions, targets, codes, traces, validation, and precedence remain unchanged. Hold decisions remain subject-free.

## Boundary

This is a pure accepted-output provenance correction and adversarial test shard. It performs no TerraBase administration, process, filesystem, network, NATS, VM, cloud, credential, or deployment operation.
