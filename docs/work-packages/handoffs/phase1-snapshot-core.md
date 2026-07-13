# Phase 1 snapshot core handoff

- Branch: `phase1/snapshot-core`
- Work package: `docs/work-packages/phase1-snapshot-core.md`
- Scope: pure immutable snapshot material, validation, and anti-rollback restore planning
- Algorithms, canonical serializers, NATS, filesystems, clocks, compatibility defaults, and composition: unchanged

## Implemented behavior

- Authority, stream, snapshot, schema, and signing-key identities require caller-supplied positive character bounds. They reject empty, whitespace/control-containing, over-bound, and malformed Unicode scalar values.
- Epoch, stream sequence, and snapshot generation are explicit positive `ulong` values. Zero/default instances fail closed; maximum values remain representable.
- State digests and signatures are nonempty opaque byte values with caller-supplied positive byte bounds, defensive input copies, fixed-time equality, and redacted formatting.
- `SnapshotSignedMaterial.TryCreate` requires every typed field and produces the complete algorithm-neutral projection passed to the signature verifier. It selects no serialization or signing algorithm.
- `SignedSnapshotValidator` requires explicit expected authority, stream, signing key, current schema, current accepted epoch and stream position, expected state digest, schema compatibility evaluator, and signature verifier.
- Validation rejects wrong scope/key, unknown or incompatible schema, compatibility/verifier failures, stale epochs, older or equal stream positions, digest mismatch, and invalid signatures through closed typed errors. Verifier exception text is discarded.
- `SnapshotRestorePlanner` performs no mutation or I/O. An accepted plan carries the snapshot/generation identity, expected restored epoch/digest, and replay start exactly one sequence after the signed snapshot position. `ulong.MaxValue` fails with a typed replay-overflow error.

## Review-sensitive semantic choice

The core treats every candidate stream sequence less than or equal to the current accepted sequence as rollback, including when the candidate epoch is newer. Epoch is checked first, so an older epoch reports `StaleEpoch`; otherwise non-advancing stream position reports `StreamRollback`. This assumes one monotonic sequence space per typed stream identity and should be retained unless a future explicitly versioned stream-reset contract says otherwise.

## Adversarial coverage

The 12 focused TUnit tests cover:

- all identity and byte bounds, malformed surrogate sequences, defensive copies, and secret-safe formatting;
- zero and `ulong.MaxValue` numeric boundaries;
- omission of each signed-material field and malformed envelope material/signature;
- exact verifier projection of all nine authenticated fields;
- wrong authority/stream/key, unknown/incompatible schema, stale epoch, older/equal stream position, digest mismatch, invalid signature, unknown verifier outcomes, and exception closure;
- a tamper-one-field matrix for every material field plus the signature; and
- deterministic replay planning, anti-rollback, exact replay start, expected digest/epoch, and overflow closure.

Verification:

```text
dotnet restore TerraScale.Orchestrator.slnx --locked-mode
dotnet build TerraScale.Orchestrator.slnx --no-restore
dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-build --no-restore -- --treenode-filter '/*/*/Snapshot*/*'
dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-build --no-restore
git diff --check
```

Result: solution build passed with zero warnings/errors; snapshot tests passed 12/12; full ControlPlane tests passed 43/43.

## Deliberate limitations

- The caller owns canonical serialization, digest calculation, signature algorithm/key lookup, schema catalog/compatibility, and durable current-position observations.
- Character bounds are .NET UTF-16 code-unit bounds. Transport adapters must separately impose explicit serialized byte limits.
- The planner is decision material only: it does not read snapshot content, replay events, mutate accepted state, or perform any NATS/file operation.
- No wall clock, schema window, crypto algorithm, identity maximum, digest/signature size, or fresh-store bootstrap default is selected.
