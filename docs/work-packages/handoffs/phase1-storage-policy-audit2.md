# Phase 1 storage expansion policy audit 2 handoff

## Proven defects and corrections

- Accepted expansion outputs previously omitted `FilesystemType` and `Layout`. An XFS/LVM volume and an ext4/partition volume could therefore authorize byte-for-byte equal `Grow` decisions even though their adapters require different typed operations. `StorageIntentScope` now carries both closed fields for every trace-created output.
- `StorageEvidenceScope` previously omitted the observed provider, device, filesystem, capacity, forecast, and performance snapshot. A proof aggregate from before provider growth compared equal to the scopes after provider growth, guest rescan, and filesystem growth. The scope now binds all seven observed byte fields and the complete `StoragePerformance` value.
- Evidence-scope validation now rejects unknown and undefined filesystem, layout, retention, and performance-tier values before evaluating checkpoint proofs.

## Preserved behavior

- Authority and failure precedence remains authority, exact evidence scope, conflicts, proof closure/order, anti-shrink and arithmetic checks, then the first unproven expansion checkpoint.
- All existing action, target, decision-code, proof, conflict, and checkpoint numeric values are unchanged. `StorageAction` remains the exact 14-value sequence `0..13`.
- Expansion remains pure and expand-only. This work adds no filesystem command, device path, provider call, adapter, default, external I/O, or deployment acceptance claim.

## Evidence

- Adversarial regression proves XFS/LVM and ext4/partition growth decisions are distinct and expose their exact typed subject.
- Capacity replay regressions distinguish provider growth, guest rescan, filesystem growth, each of the seven byte fields, and every performance component.
- Changed snapshots fail with `WrongEvidenceScope` and cannot authorize mutation. Undefined closed enums fail at the same scope-validation precedence.
- The existing generated crash/replay properties retain the exact first-unproven-step action, target, code, numeric trace, and checkpoint sequence.

## Non-claims

This is Phase 1 pure-policy evidence only. It does not qualify provider, block-device, ext4/XFS, TerraBase, systemd, OCI, SmolVM, or destructive-storage behavior and does not mint deployment authority.
