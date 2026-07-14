# Phase 1 security enrollment generation audit 4

## Goal

Close the proven enrollment replay gap where request-local principal, bootstrap, and attestation generations could agree coherently while all being stale or future relative to the current principal generation.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Security/SecurityModels.cs`
- `src/TerraScale.Orchestrator.ControlPlane/Security/SecurityDecisionEngine.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/SecurityFourthAuditRegressionTests.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/SecurityDecisionTests.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/IdentityNetworkPropertyTests.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/IdentityNetworkSnapshotTests.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/SecurityAcceptedOutputGapTests.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/SecurityCompletenessData.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/SecurityPolicyCompletenessPropertyTests.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/SecurityPolicyReplayCorpus.v1.json`
- `docs/work-packages/phase1-security-enrollment-generation-audit4.md`
- `docs/work-packages/handoffs/phase1-security-enrollment-generation-audit4.md`

## Contract

Every `EnrollmentRequest` supplies a non-null `CurrentPrincipalGeneration`. Enrollment can issue or attest an identity only when the expected principal, selected bootstrap evidence, selected attestation evidence, and current-principal high-water agree exactly. A coherent lower or higher generation is rejected at the existing `GenerationCurrent` reason, including the missing-attestation branch. Accepted issue and attestation intents retain the exact request and current-principal generation object.

`SecurityDecisionCode.GenerationCurrent` remains numeric value 8 and keeps its existing trace position. Its observed value is the expected principal generation and its required value is the current-principal high-water. No generation arithmetic is introduced, including at `ulong.MaxValue`.

## Validation matrix

- Exact current generation with valid attestation: authorize `IssueIdentityIntent`.
- Exact current generation with missing attestation: authorize `AttestIdentityIntent`.
- Coherent lower generation with valid or missing attestation: reject and emit only `HoldSecurityOperationIntent`.
- Coherent future generation with valid attestation: reject and emit only `HoldSecurityOperationIntent`.
- Null current generation: construction fails.
- Public construction surface: exactly one ten-parameter constructor in the declared order, with no optional/default parameters or public static factory.
- `ulong.MaxValue` exact match: accepted without overflow.
- Repeated evaluation under `en-US`, `tr-TR`, `ar-SA`, and `ja-JP`: identical ordered trace.
- Completeness, construction-closure, strict corpus replay, and 1,000-case permutation properties remain green. The strict corpus saves coherent stale, coherent future, and stale missing-attestation failure seeds as variants 16, 17, and 18.

## Boundary

This is a deterministic in-memory authorization-contract correction. `SecurityGeneration` remains distinct from the deferred process-wide `SecurityEpoch`. The change does not prove external identity authenticity, attestation validity, persistence freshness, distributed replay prevention, or multi-writer ordering. It performs no cryptography, credential handling, KMS/Vault access, network, filesystem, cloud, deployment, or other external side effect.
