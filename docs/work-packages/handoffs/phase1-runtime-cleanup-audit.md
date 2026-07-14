# Phase 1 runtime cleanup audit handoff

## Scope

- Audits only the pure runtime lifecycle and self-update policy against `ORCHESTRATOR.md`.
- Starts no process, unit, container, VM, network, filesystem, provider, deployment, or sibling-repository action.
- Selects no runtime driver, artifact, timeout, compatibility, retention, or rollout default.

## Production defects proven and corrected

`CleanupRuntimeIntent` previously retained only its operation identity and a derived array of ephemeral volume identities. It discarded the exact validated lifecycle request, including allocation, node, writer epoch, generation, admission policy, workload/config/artifact identities, and the retention evidence from which cleanup authority was derived. That was insufficient persisted authorization context for an external deletion.

The derived array was also exposed as `IReadOnlyList<RuntimeVolumeId>`. The runtime type remained `RuntimeVolumeId[]`, so a caller could cast it back to the array and replace an authorized ephemeral identity after the decision.

Cleanup now retains the exact immutable `RuntimeLifecycleRequest` and exposes its derived ephemeral-only allowlist through one non-castable read-only collection. Retained volume identities remain absent. The decision engine, authorization results, reason trace, enum values, and numeric IDs are unchanged.

## Adversarial coverage

- A valid stopped allocation reaches the cleanup intent and preserves the exact validated request reference.
- The cleanup allowlist exactly matches the ephemeral subset of the captured specification and excludes its retained volume.
- The public allowlist cannot be cast to its backing array, rejects indexed mutation, and remains unchanged after the attempt.
- Every mutating lifecycle intent retains its exact request. The read-only health-check, executor-observation, and hold intents are explicitly excluded.

## Contract inventory

- `RuntimeDecisionCode`: 21 values with IDs `1..21`, unchanged.
- `RuntimeDecisionOutcome`: 4 values, unchanged.
- Runtime intent subtypes: 21, unchanged.
- Lifecycle phases/actions/executor call statuses: 10/4/4, unchanged.
- Normal lifecycle trace: 15 entries in the existing order; duplicate/conflicting health evidence still returns the existing two-entry hold trace.
- Self-update contracts and trace are unchanged.

## Evidence boundary

This is pure feature-shard evidence only. It does not implement or qualify executor adapters, persistence, systemd, containerd, filesystem deletion, VM/cloud behavior, L0/L0C, mutation testing, deployment, or production acceptance.
