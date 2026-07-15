# Phase 1 runtime self-update completeness shard handoff

## Scope

- Audits only the pure A/B self-update policy and its immutable inputs/outputs.
- Starts no process, systemd unit, container, VM, network, filesystem, provider, deployment, or sibling-repository action.
- Selects no signing implementation, timeout, soak duration, compatibility generation, architecture, or rollout default.

## Production defects proven and corrected

1. Exact, explicitly `Incompatible` N/N-1 evidence after local verification was classified as a generic denial. The local-known-good rollback policy now authorizes one typed rollback at `LocalHealthVerified`, `RegionalCompatibilityVerified`, `SlotCommitted`, or `OldSlotRetainedUntilSoak`. Earlier activation phases, rollback phases, terminal rollback failure, mismatched compatibility scope, and `Missing`/`Unknown` compatibility remain denied.
2. A failed target-generation health result could emit `RollbackUpdateIntent` before held evidence was examined. That allowed rollback authorization even when the required rollback artifact was missing. Once an in-flight executor call has been safely classified, every held prerequisite is now denied before either health- or compatibility-triggered rollback.

`CompatibilityExact=Rejected` remains an honest trace for an explicit incompatible result: it says the compatibility acceptance gate did not pass. The engine treats only an exact-scope, explicit `Incompatible` result at one of the four rollback-eligible checkpoints as a recoverable failure. It does not treat a replayed scope or absent/unknown evidence as a rollback authorization.

## Independent deterministic coverage

- 1,000 distinct seeded operations independently mutate every forward and rollback evidence field: release, artifact, digest, signature, signing profile, architecture, generation, availability, and verification. Each mutation binds the exact denial/hold code, outcome, closed trace cardinality, and operation identity.
- 1,000 cases distribute exact incompatibility across all four rollback-eligible checkpoints and compare every trace entry, outcome, observed value, and required value against an independent oracle. The emitted rollback intent retains the exact immutable request.
- 1,000 cases distribute incompatibility across every pre-local-verification and rollback/terminal phase and prove none can mint rollback.
- 1,000 mixed-precedence cases cover `Accepted`/response-lost observation, failed health plus missing rollback material, digest/signature mismatch, stale epoch, non-next generation, simultaneous exact compatibility and health failure, replayed compatibility scope, terminal rollback failure, and missing/unknown compatibility.
- 1,000 identical-input cases compare the complete decision rendering under `en-US` and `tr-TR`/`ar-SA`/`ja-JP`, changing both current culture and UI culture and reversing health enumeration order.

The pre-existing hostile-enumerable runtime snapshot shard remains the canonical coverage for exact-limit, maximum-plus-one, endless, iterator-phase failure, fatal exception propagation, and dispose-mutation behavior; this shard does not duplicate it.

## Verification

- Focused ControlPlane Release tests: 441/441 passed after rebasing the latest central branch.
- `git diff --check`: clean.

This is bounded feature-shard evidence only. It is not full L0/L0C, mutation, deployment, runtime-boundary, or acceptance evidence.
