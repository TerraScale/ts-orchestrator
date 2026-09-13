# Native backup boundary replacement

The updated workspace D-29 and workspace goal assign backup implementation to
TerraBase's native Rust subsystem. Inspection found no external backup
launcher or module dependency in the orchestrator. The remaining coupling was
in lifecycle interfaces, reaper operation names, runbook output and comments.

The reaper now calls `StopNativeBackup`, records `pause/native-backup`, and
requires NATS reaper envelope schema 2. Schema 1 and old stop-operation names
are refused, including entries that had not yet reached the stop phase. The
existing state revision counter and global lease schema are unchanged.

Add-region dry-run output now uses `backupTargets`. Regional bucket purposes,
names, ownership, versioning and lifecycle values are unchanged. Restore-drill
and production adapter contracts now describe native TerraBase ownership and
require engine lifecycle operations rather than external process supervision.

The focused race tests passed for `reaper`, `cmd/orchestrator`, `estate` and
`restoredrill`. The new real-NATS regression publishes a version-1 reaper
envelope under a live global lease, proves that Load refuses it and Save cannot
overwrite it, and verifies the original message bytes and sequence remain.
It also rejects old stop-operation names with and without a cycle suffix.
Existing retry, admission, CAS, quorum and restart tests pass using schema 2.

`make check` passed formatting, vet, build and the complete portable race suite.
Output is retained in `native-backup-boundary-portable-2026-09-05.txt`.

The change does not implement native backup capture, a concrete TBEP mutation
adapter, or migration of old reaper histories. Old histories must remain intact
for an audited transition based on engine evidence. Native readiness, restore
drills, PITR and resource-efficiency comparisons remain unqualified. See
[the lifecycle contract](../contracts/native-backup-lifecycle.md).
