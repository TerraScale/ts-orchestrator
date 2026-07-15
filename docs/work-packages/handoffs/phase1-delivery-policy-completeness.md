# Phase 1 Delivery policy completeness handoff

## Defects proven on predecessor `079f4c0`

- An accepted source plan dropped the source signature and schema/dependency attestation identities from `PlanApplyIntent`.
- An accepted promotion consumed but dropped the tests attestation from `PromoteArtifactIntent`.
- Promotion and rollout contracts could not distinguish `linux-arm64` from `linux-x64`, despite architecture-specific artifact/digest promotion requirements.
- Rollout availability, stage, completion, advance, and rollback contracts carried signature references without the expected signing identities.

These were pure accepted-output and evidence-binding defects. No adapter, deployment, cryptographic verification, or external-system behavior was exercised.

## Reviewed resolution

- Added a closed Delivery architecture catalog and exact architecture/signer binding across promotion and rollout inputs and outputs.
- A forward artifact and its rollback artifact for one selected rollout target must use the same target architecture. Shared signature reference IDs remain permitted; no unrelated signature-inequality policy was added.
- Retained the source signature plus schema/dependency attestations in the plan intent and the tests attestation in the promotion intent.
- Added direct denial cases for forward and rollback availability signer mismatch, current-stage signer mismatch, completed-cell signer mismatch, both architecture mismatch directions, and combined-failure precedence.
- Preserved caller-owned rollout order and all existing technical collection limits. No regional order, signer, architecture, or retry default was selected.

## Evidence

- Two deterministic property families execute 1,000 generated cases each. Their cases rotate through 6 source/promotion modes and 23 rollout modes; the count is not 1,000 per individual mode.
- Exact renderings include every field of Plan, Verify, Promote, Stage, Advance, Rollback, Hold, Error, and Trace outputs and compare `en-US` with `tr-TR`, `ar-SA`, and `ja-JP` while restoring both current cultures.
- Undefined observed Delivery enums fail closed before a mutation intent.
- The pre-existing embedded Delivery/TerraBase replay corpus remains content-identical because its expected source outcomes did not change; its construction helper now supplies explicit architecture and signing identities.

## Validation on rebased tree

- `dotnet restore TerraScale.Orchestrator.slnx --locked-mode` — succeeded.
- `dotnet build TerraScale.Orchestrator.slnx --no-restore -c Release -m:1 -warnaserror` — succeeded with zero warnings and zero errors.
- Delivery-focused Release executable — 29 passed, 0 failed.
- Full ControlPlane Release executable — 464 passed, 0 failed.
- `git diff --check` — clean.

This handoff makes no L0, L0C, VM, provider, deployment, or production-acceptance claim.
