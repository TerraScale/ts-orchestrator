# Phase 1 delivery and TerraBase property/replay shard

## Goal

Add deterministic, bounded property and saved-counterexample coverage for the existing pure Delivery/GitOps/release and TerraBase topology/recovery decision cores. Harden their caller-controlled collection snapshots without selecting business policy.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Delivery/**`
- `src/TerraScale.Orchestrator.ControlPlane/TerraBase/**`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/DeliveryTerraBase*`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj`
- `docs/work-packages/phase1-delivery-terrabase-properties.md`
- `docs/work-packages/handoffs/phase1-delivery-terrabase-properties.md`

## Required evidence

- At least 1,000 generated cases per property family with independent expected outcomes.
- Identity, generation, digest, signature, stale/conflicting/duplicate/reordered evidence, rollback, terminal replay, quorum/membership, culture, and permutation checks where exposed by the existing cores.
- Strict, bounded, whole-file-content-addressed embedded replay corpus whose input changes affect replay.
- Technical collection caps, max/max+1 and hostile iterator coverage, defensive copies, generic secret-safe ordinary failures, and fatal exception propagation.
- Construction-closed authorizing outputs and closed observed enum catalogs.

## Exclusions

No Git, process, filesystem runtime, network, cloud, package/tool selection, deployment, or L0 evidence. Technical caps are not rollout-cell, dependency, runner, member, quorum, or backup business policy.
