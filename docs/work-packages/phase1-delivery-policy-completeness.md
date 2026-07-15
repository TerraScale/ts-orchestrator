# Phase 1 Delivery policy completeness shard

## Scope

- Pure Delivery source, promotion, and rollout contracts under `src/TerraScale.Orchestrator.ControlPlane/Delivery/**`.
- Delivery-only completeness properties in `tests/TerraScale.Orchestrator.ControlPlane.Tests/DeliveryPolicyCompletenessPropertyTests.cs`.
- No Git, Forgejo, NATS, process, filesystem, network, provider, signing implementation, deployment, or acceptance evidence.

## Contract map

- `ORCHESTRATOR.md:354-367`: promotion and rollout bind the selected architecture and its exact digest; ARM64 and x64 artifacts are not interchangeable.
- `ORCHESTRATOR.md:924-956`: source verification retains the accepted signature through the typed plan/apply boundary.
- `ORCHESTRATOR.md:968-997`: promotion retains the exact test attestation and N/N-1 compatibility proof; rollout reuses one exact signed candidate and locally available rollback artifact.
- `ORCHESTRATOR.md:1134-1135`: pure Delivery decisions cover staged promotion, rollback, one-writer release rules, and exact-artifact reuse.
- Accepted `phase1-delivery-core` handoff: authorizing outputs carry exact proofs, rollout order is caller-owned, and policy defaults remain outside this shard.

## Changes and evidence boundary

- Add a closed `DeliveryArchitecture` catalog and bind it across promotion subjects, release specifications, availability observations, stage/completion evidence, and stage/advance/rollback intents.
- Require forward and rollback architecture equality for one rollout target; a rollout cannot substitute an x64 rollback on an ARM64 target or the inverse.
- Retain source signature in `PlanApplyIntent` and tests attestation in `PromoteArtifactIntent` instead of dropping accepted proof at the authorizing boundary.
- Add two deterministic 1,000-case independent-oracle families covering every output field, all trace fields, forward/rollback availability and stage/completion signer mismatch, architecture mismatch, denial precedence, completion order, terminal replay, exact rollback, input permutation, and en-US/tr-TR/ar-SA/ja-JP stability.
- Reject every undefined observed Delivery enum before a mutation intent.

The existing embedded Delivery/TerraBase replay corpus is unchanged: its Delivery source behavior and expected outcomes are unaffected, and its helper now supplies the explicit architecture required by the strengthened contract.
