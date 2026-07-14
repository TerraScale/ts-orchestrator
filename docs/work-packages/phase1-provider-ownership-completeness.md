# Phase 1 provider ownership completeness shard

## Goal

Adversarially complete the pure provider ownership and Pulumi handoff policy without invoking a provider, SDK, network, process, filesystem, or deployment lane.

## Scope

- Bind every provider call observation to the exact immutable operation context it attests.
- Bind Pulumi handoff acceptance to the caller-supplied current accepted bootstrap-generation high-water; reject only lower candidates while preserving equal retries and forward progress.
- Exercise 1,000 deterministic cases in each property family, rotating across every operation-fingerprint dimension, provider call lifecycle outcome, closed provider action, and handoff inventory/proof dimension.
- Preserve stable existing numeric trace IDs, typed-intent/output closure, response-lost idempotency, durable higher-epoch resume, defensive snapshot bounds, fatal exception propagation, and tag-not-authority boundary.
- Reuse the existing pinned provider replay corpus and enumerable-boundary shard; do not duplicate those fixtures or claim mutation, NATS, cloud, OCI, Pulumi, L0/L0C, L3S, L4, or deployment evidence.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Providers/**`
- provider call-site updates in existing tests
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/ProviderOwnershipCompletenessPropertyTests.cs`
- this work package and its handoff

## Verification

Run the focused completeness shard, the complete ControlPlane test executable, a warnings-as-errors Release build, and `git diff --check`.
