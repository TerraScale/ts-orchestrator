# Phase 1 CI evidence report accepted-output audit 4

## Goal

Close the proven accepted-output collision where distinct, fully validated evidence reports with the same claimed canonical payload digest produced equal authorized evidence decisions.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Evidence/EvidenceGate.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/CiEvidenceReportAudit4CounterexampleTests.cs`
- `docs/work-packages/phase1-ci-evidence-report-audit4.md`
- `docs/work-packages/handoffs/phase1-ci-evidence-report-audit4.md`

## Contract

Every accepted `EvidenceDecisionSubject` retains the exact validated `EvidenceSubject` report reference in addition to its payload digest. Decision equality compares the digest and the report's canonical structural content, so exact independently reconstructed or collection-permuted reports replay equally while distinct reports cannot collapse merely because a caller supplied the same digest. Holds remain subject-free.

The existing manifest/signing authorization scope is unchanged. This audit does not retain the policy, verifier identity, or opaque signature bytes and does not change validation, policy, signature, freshness, lane, target, action, code, trace, or precedence behavior.

## Boundary

This is a pure in-memory accepted-output provenance correction. It does not calculate or authenticate the claimed canonical digest, qualify evidence producers or signers, release a credential, dispatch CI work, or perform process, filesystem, network, NATS, VM, cloud, registry, signing, deployment, or other external operations.
