# Phase 1 evidence accepted-scope audit

## Goal

Close the proven collision where two authorized pre-deployment evidence decisions with different manifest and verified signing provenance produced equal accepted outputs.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Evidence/EvidenceGate.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/EvidenceCoreTests.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/EvidencePolicyCompletenessPropertyTests.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/SnapshotEvidencePropertyTests.cs`
- `docs/work-packages/phase1-evidence-accepted-scope-audit.md`
- `docs/work-packages/handoffs/phase1-evidence-accepted-scope-audit.md`

## Contract

An accepted decision retains its exact manifest identity and lane, gate target, signing profile, signing identity, signature identity, generation, and expiry sequence. Rejected decisions retain no authorization scope. Existing error codes and evaluation precedence do not change.

## Boundary

This is a pure accepted-output change and adversarial test shard. It performs no signing, verification implementation, credential, process, filesystem, network, NATS, VM, cloud, or deployment action.
