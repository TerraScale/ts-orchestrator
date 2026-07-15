# Phase 1 native GitOps, CI, and release decision core

## Predecessor

- Contract steward commit: `a1ecba0`
- Repository placement, signing technology, approval policy, rollout windows, and retention values remain explicit owner/caller inputs.

## Goal

Implement pure GitOps source reconciliation, CI trust-zone scheduling, artifact promotion, and release/CD correctness state machines from `ORCHESTRATOR.md:924-1010`. It emits typed source/runner/release intents only.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Delivery/**`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Delivery*.cs`
- `docs/work-packages/handoffs/phase1-delivery-core.md`

## Required behavior

- Immutable bounded source/ref/commit/tree/manifest/pipeline/job/runner/trust-zone/artifact/digest/signature/attestation/release/cell/operation identities; positive generations/attempts; closed source/job/promotion/rollout/rollback states.
- GitOps accepts immutable commit/tree/digest evidence, validates schema and dependency proofs, produces deterministic plan/apply intent, and never treats branch movement or webhook delivery as authority. Same desired generation/digest is idempotent; lower/conflicting generations fail closed.
- CI schedules jobs only onto compatible explicit trust zones/capabilities with fresh runner evidence; untrusted product code cannot receive production secrets/provider authority or mutate the control plane. Interrupted jobs are retried only under explicit attempt/idempotency policy.
- Promotion requires exact source tree, dependency lock, generated schemas, tests/evidence attestation, artifact digest, signing identity, approval, and compatibility proof. Any source/dependency/schema/binary change invalidates evidence.
- CD uses exact signed artifact and desired generation, local forward+rollback availability, staged health proof, disruption/availability authorization evidence, and deterministic rollback/hold rules. Process exit alone is never success.
- Emit closed fetch/verify/plan/dispatch/promote/stage/advance/rollback/hold intents with exact proofs and stable code/numeric trace; no Git command, script, pipeline text, secret, callback, process, network, or I/O.
- Defensive copies; culture/permutation/replay determinism; branch race; duplicate webhook; dependency ordering; trust-zone escape; lost runner; evidence invalidation matrix; N/N-1 compatibility; staged failure/rollback; and secret-safe/reflection tests.
- No Git/Forgejo/process/filesystem/network/clock, signing implementation, rollout default, approval default, or mutation.

## Verification

`dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj`

