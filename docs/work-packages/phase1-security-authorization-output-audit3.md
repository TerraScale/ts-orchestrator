# Phase 1 security authorization output audit 3

## Goal

Close the proven accepted-output collision where capability authorization intents discarded the selected principal evidence, matching grant, and accepted generation high-water provenance.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Security/SecurityModels.cs`
- `src/TerraScale.Orchestrator.ControlPlane/Security/SecurityDecisionEngine.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/SecurityThirdAuditRegressionTests.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/SecurityPolicyCompletenessPropertyTests.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/SecurityCompletenessData.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/SecurityPolicyReplayCorpus.v1.json`
- `docs/work-packages/phase1-security-authorization-output-audit3.md`
- `docs/work-packages/handoffs/phase1-security-authorization-output-audit3.md`

## Contract

An accepted `AuthorizeCapabilityIntent` retains the exact selected principal evidence and matching grant plus expected/current principal, policy/current-policy, and current-revocation generations. Existing operation, principal, capability, and resource projections remain. Denials retain only the hold intent. Error numerics, trace order, authorization policy, and precedence do not change.

## Boundary

This is a pure accepted-output provenance correction and adversarial test shard. It performs no cryptography, secret handling, certificate issuance, vault access, identity verification, process, network, NATS, VM, cloud, credential, or deployment operation.
