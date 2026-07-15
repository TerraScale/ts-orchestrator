# Phase 1 snapshot and restore core

## Goal

Implement the pure snapshot acceptance/restore decision core from `ORCHESTRATOR.md:545-550`: snapshots bind schema version, signed stream position, state digest, and fencing epoch; restore refuses rollback.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Snapshots/**`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Snapshot*.cs`
- `docs/work-packages/handoffs/phase1-snapshot-core.md`

## Required behavior

- Immutable bounded authority/stream/snapshot/schema/key identities; positive epoch/stream sequence/generation; opaque nonempty state digest/signature.
- Complete algorithm-neutral signed material and caller-supplied typed signature verification outcome; verifier exceptions become closed errors and never leak text.
- Pure create-material, validate, and restore-plan decisions using explicit current accepted epoch/stream position/schema compatibility and supplied signature verifier.
- Reject wrong authority/stream/key, malformed/unknown/incompatible schema, stale epoch, older/equal stream rollback where inappropriate, digest mismatch, invalid signature, and signature material field omission.
- A restore plan emits replay start after the exact snapshot position and expected restored digest/epoch; it never mutates state or performs I/O.
- Defensive byte copies, secret-safe formatting, invariant canonical material projection, overflow boundaries, tamper-one-field matrix, verifier failure, replay determinism, and restore anti-rollback tests.
- No signing algorithm, serializer, NATS, filesystem, time, or compatibility-window default.

## Verification

`dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj`
