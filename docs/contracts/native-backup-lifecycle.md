# Native backup lifecycle boundary

Workspace D-29 and TerraBase ADR 0046 assign backup capture, WAL/checkpoint
coordination, shared scheduling, uploads, PITR, restore, and branching to
TerraBase's native Rust subsystem. The orchestrator owns regional OCI buckets,
lifecycle policy and key authority, and requests engine lifecycle work through
the admitted TBEP contract. It does not launch an external Litestream binary or
supervise a process per database.

The orchestrator previously exposed external-backup terminology in its reaper
port and add-region runbook. No external binary launcher was found in its Go
implementation. Those contracts now use:

- `Executor.StopNativeBackup` and `DatabaseAdapter.StopNativeBackup` for the
  selected database's native backup stream;
- `pause/native-backup` for the reaper's durable stop operation; and
- `backupTargets` in add-region dry-run JSON.

The engine adapter must verify the retained native snapshot and residency lock,
coordinate closing the database with the engine's WAL/checkpoint capture, and
acknowledge stopping that database's backup stream. It must preserve the retained
restore point and the shared workers used by other databases. A stopped timer or
process exit is insufficient evidence of a recoverable backup. The reaper still
orders snapshot, close, backup stop, and notice, with idempotent retry keys and
fresh effect-authority checks. Reactivation remains engine-owned.

The regional bucket purpose remains `database-backup`. Existing bucket names,
ownership, versioning, and D-29 tiering rules are preserved: Infrequent Access
after one day, Archive after seven days, and the declared history expiry. This
change does not recreate buckets or change residency.

## Retained reaper state

The NATS reaper envelope now uses schema version 2. `State.Version` remains the
monotonic state revision counter; it is not the envelope schema version.
Version-1 envelopes are refused before reconciliation, including active records
without a completed stop operation. Old `pause/litestream` operations, with or
without a cycle suffix, are also refused by state validation.

The reader does not relabel, delete, or overwrite old state to start fresh. Old
snapshot and stop acknowledgements cannot establish native-backup completion.
Any migration must preserve notice, reactivation, deletion-fence and key-history
evidence while obtaining native engine observations under current authority.
That migration is not implemented. Retain version-1 histories for that review;
manually changing their schema number does not qualify them.

## Remaining production work

These changes define the orchestrator boundary. They do not implement the native
backup subsystem or a concrete TBEP mutation adapter. Engine backup readiness,
restore-to-new-database/PITR behavior, resource sharing, performance comparisons,
and daily recovery drills still require producer evidence and integrated tests.
Missing adapters continue to prevent production composition. The method and
runbook changes must not be treated as a passing backup-readiness gate.
