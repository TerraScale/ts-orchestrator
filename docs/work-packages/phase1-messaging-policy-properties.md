# Phase 1 messaging policy property/replay shard

## Goal

Add deterministic, independently-oracled property and saved-counterexample coverage to the existing pure messaging topology, replacement, and partition decision core. Harden only caller-controlled collection capture defects proven during that audit.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Messaging/**`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/MessagingPolicy*`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj`
- `docs/work-packages/phase1-messaging-policy-properties.md`
- `docs/work-packages/handoffs/phase1-messaging-policy-properties.md`

## Required evidence

- At least 1,000 generated cases each for replacement precedence, partition authority/generation precedence, and dual-plane isolation.
- Independent expected outcomes, exact intent subjects, permutation and culture replay, and construction closure for all authorizing intents and decisions.
- A strict UTF-8 byte-bounded, whole-file SHA-256-pinned embedded replay corpus with input-sensitive replay fingerprints.
- Defensive capture at the public technical cap, rejection before reading an extra `Current`, literal endless and disposal-mutation sources, secret-safe ordinary iterator failures, and fatal exception propagation.
- Hostile `IReadOnlyList` count/enumerator behavior in compatibility decisions while preserving `MaximumResources` as separate business policy.

## Exclusions

This shard contains no NATS client/server package, process, socket, filesystem runtime, network, cloud, retry loop, or version selection. It does not claim L0C or any real NATS evidence. The 4,096-item snapshot limit is a non-business technical memory bound, not a membership, replica, resource, rollout, or quorum policy.
