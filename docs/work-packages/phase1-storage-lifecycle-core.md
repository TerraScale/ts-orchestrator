# Phase 1 storage lifecycle and expansion core

## Predecessor

- Contract steward commit: `a1ecba0`
- Filesystem, performance tier, thresholds, growth increment, lead time, SLO/RPO, and deletion policy values remain caller inputs.

## Goal

Implement the pure storage identity, single-writer, create/attach, expansion, and deletion authorization state machines from `ORCHESTRATOR.md:758-841`. It emits typed provider/guest/application intents only.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Storage/**`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Storage*.cs`
- `docs/work-packages/handoffs/phase1-storage-lifecycle-core.md`

## Required behavior

- Immutable bounded claim/provider-volume/attachment/node/workload/member/filesystem/operation/backup/fence identities; checked byte/performance/generation/epoch quantities; closed filesystem/layout/retention/action/observation catalogs.
- Exact volume ownership and identity bind provider ID, cell/workload/member/claim, domain, attachment, encryption-key reference, filesystem UUID/type/layout/mount purpose, observed/requested/provider/block/filesystem/used/free bytes, performance, retention, backup, generation, writer fence, and operation.
- New blank format is authorized only with exact provider/owner/blank proof/current fence. Recognized volumes never format. Single-writer read/write attachment cannot overlap; reattach requires stop proof, lease revocation, provider detachment convergence, new writer epoch, and health verification.
- Restartable expansion follows the documented irreversible sequence. Provider size alone is never success; a crash resumes at the first unproven step and never issues duplicate growth. Expansion never shrinks and serializes against all caller-declared conflicting operation classes.
- Permanent deletion is unrepresentable without every topology, quorum/replication, database-reference, backup/retention, owner/fence, quarantine/disposable, and post-delete audit proof. The core authorizes an exact deletion intent but never performs it.
- Emit closed observe/create/attach/classify/format/mount/rescan/extend/grow/verify/detach/delete/hold intents and stable code/numeric traces; no device path, mount command, shell text, secret, callback, SDK type, or I/O.
- Defensive copies; culture/permutation/replay determinism; wrong owner/fence; dual writer; recognized-format denial; crash at every expansion step; size disagreement; shrink/overflow; conflict serialization; permanent/elastic deletion proof matrices; and secret-safe tests.
- No storage/provider/filesystem API, process, wall clock, threshold/growth/default filesystem/performance value, or mutation.

## Verification

`dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj`

