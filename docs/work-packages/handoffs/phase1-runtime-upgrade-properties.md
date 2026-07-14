# Phase 1 runtime self-upgrade deterministic property shard handoff

## Scope

- Chooses A/B self-upgrade as the cohesive high-risk shard because its pure decision authorizes orchestrator binary activation, slot switching, commit, retention, and rollback.
- Adds four independent deterministic families with exactly 1,000 seeded cases each: every persisted A/B checkpoint, exact artifact/rollback/compatibility/epoch/operation fences, lost-response versus failed-health recovery, and culture/health-permutation replay.
- Seeds materially reconstruct operation, node, allocation, release, artifact, signature, generation, and evidence identities; 1,000 distinct operation identities are asserted. Corpus replay compares an exact reconstructed fingerprint, proves emitted intents retain the request operation, and proves a mutated seed changes the fingerprint.
- Invalid variants bind exact `RuntimeDecisionCode` and outcome. Recovery variants bind exact observe/rollback intent and `CallSafe`/`ReadinessComplete` evidence.
- Adds a 19-entry embedded replay corpus pinned as a whole file to SHA-256 `d869460ff66604d33babe48d443351ce3de201ab046789e55afe985b27279376`. Its bounded reader and strict parser reject over 8,192 bytes, comments, trailing commas/data, excess depth/entries, field drift/duplicates, duplicate identities/seeds, zero/negative/out-of-range/type-invalid seeds, and an invalid closed `(variant, expected)` pair. Replay IDs use a canonical lowercase ASCII token grammar with an exact 64-character boundary. The terminal rollback-failed checkpoint is pinned to a denied `RollbackPossible` outcome.
- Proves `RuntimeDecision` has no public constructor or non-operator factory and no `RuntimeIntent` subtype has a public constructor, so caller code cannot mint an accepted activation.

## Production hardening

- Replaces unbounded caller-enumerable capture in `RuntimeEnums.Copy` and `CopyDistinct` with one shared snapshot helper and public documented `RuntimeTechnicalLimits.MaximumCapturedItems = 4096`.
- The cap is technical denial-of-service protection, not health, lifecycle, soak, compatibility, or rollout policy.
- Constructor signatures and post-capture null/enum/duplicate semantics are unchanged. Exact maximum succeeds; max+1/infinite sources reject before the extra `Current`; ordinary iterator failures become generic secret-safe `ArgumentException` without inner exceptions; `OutOfMemoryException`, `StackOverflowException`, and `AccessViolationException` propagate from every iterator phase; dispose mutation cannot alter the captured request.

## Verification

- Focused ControlPlane Release tests: 330/330 passed.
- Full solution Release tests: 511/511 passed.
- Full solution Release build: succeeded with zero warnings and zero errors.

This is bounded deterministic feature-shard evidence, not full L0 or deployment qualification. It starts no process, VM, network, cloud, filesystem adapter, or sibling-repository change and selects no artifact signing technology, timeout, compatibility, or rollback policy value.
