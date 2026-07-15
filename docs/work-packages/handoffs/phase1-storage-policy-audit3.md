# Phase 1 storage destructive-output audit 3 handoff

## Proven defect and correction

- Exact deletion evidence already bound the volume retention policy and verified backup identity, but the accepted intent subject discarded both values. Consequently, an elastic-quarantine deletion and an explicitly-disposable deletion could emit equal `Delete` decisions after satisfying different destructive policy gates. The same collision existed between decisions authorized against different verified backup identities.
- `StorageIntentScope` now retains the exact `StorageRetention` value and `StorageBackupId` instance copied from `StorageVolumeRecord`. All decisions constructed from a volume trace, including holds and non-deletion actions, preserve the same closed subject shape.

## Preserved behavior

- Authority, permanent-retention, evidence-scope, proof-closure, retention-specific, provider-convergence, and post-delete-audit precedence is unchanged.
- No action, target, decision-code, proof, checkpoint, or enum numeric value changed. The intent subject is the exact 15-property closed shape.
- Intent and trace rendering remains opaque; the verified backup identifier is not written by `ToString()`.

## Evidence

- Adversarial regressions prove retention-policy-only and backup-identity-only deletion decisions are unequal, while retaining the exact accepted values and backup object instances.
- The generated storage oracle checks retention and backup identity across every create, format, reattach, expansion, deletion, and hold/action path it exercises.
- The fixed replay trace fingerprint includes retention and backup, and construction-closure tests prevent callers from minting accepted decisions, traces, or intent subjects.

## Non-claims

This closes only the pure-policy binding of the accepted retention and verified-backup subject. It does not qualify a deletion adapter, provider API, filesystem, backup system, destructive lab run, or deployment acceptance, and it does not claim that every possible storage acceptance concern has been audited.
