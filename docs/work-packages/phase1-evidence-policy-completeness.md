# Phase 1 evidence policy completeness shard

## Goal

Adversarially complete the existing pure pre-deployment evidence policy without claiming or executing any deployment evidence lane.

## Scope

- Require every suite declared by an evidence subject to meet the caller-supplied test, property, branch, mutation, model-schedule, and flake floors, including suites outside the minimum required-domain set.
- Require the declared suite-domain and model-corpus-domain inventories to match exactly so an orphan suite or corpus cannot be carried by an authorizing manifest.
- Exercise 1,000 deterministic cases for every suite floor, suite/corpus domain parity under permutation, and exact generation/expiry/signing denial outputs with complete numeric traces.
- Retain caller ownership of domain requirements and all numeric thresholds. No threshold, signer, verifier, clock, credential, or execution result is invented.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Evidence/EvidencePolicy.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/EvidencePolicyCompletenessPropertyTests.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/SnapshotEvidencePropertyTests.cs`
- `docs/work-packages/phase1-evidence-policy-completeness.md`

## Boundary and non-claims

This shard changes only pure policy evaluation and pure tests. It performs no filesystem, process, network, NATS, VM, cloud, credential, deployment, signing, or KMS action. It does not claim that L0, L0C, dual-architecture, mutation, fuzz, model, signature, or deployment evidence has executed or passed.
