# TS-641 preparation inspection, 2026-10-07

Read-only inspection of the existing GRU and SFO regions through
2026-10-07 20:39 UTC; no resources changed during this inspection. This is a
pre-apply record. Later execution results must be recorded separately.
See the [live preparation record](ts-641-replication-20261007.md) for the
subsequent partial apply and its retained resource IDs.

| Prerequisite | Observation |
| --- | --- |
| Source backup shipping | `gru-1-backup/v1/` contains database and `_system` snapshots. Current per-file lag and production drill success were not measured. |
| Durable configuration | GRU has `TS_HOST_ENROLLMENT`, `TS_ROLLOUTS`, `TS_SERVICE_SET` under `kv-snapshot/v1/gru/`. SFO has enrollment and spec under `kv-snapshot/v1/sfo/`. |
| Object replication | Disabled on `gru-1-{backup,head}` and `sfo-1-{backup,head}`. No dedicated replicas observed. |
| Vault replication | Both existing DEFAULT Vaults report `isVaultReplicable=true`; no replicas observed. |
| Replication IAM | No Object Storage replication or Vault service replica-management grants observed in either control compartment, their TerraScale parent, or the tenancy. Regional Object Storage bucket-key grants exist. |
| Target availability | SFO `/healthz`, `/readyz`, OIDC discovery and Atlas inspection passed in the delegated audit. |

`ts-orch disaster-recovery replicate --config
deploy/oci-region/disaster-recovery.json` passed against live OCI without
`--apply`. The JSON plan names four mirrors, four versioned historical seed
buckets and two Vault replicas. It validates the pinned bucket identity,
compartment, encryption key, and the Vault/key relationship. OCI source object
HEAD on a nonexistent object returned 404 without an error code, so backfill
uses GET to distinguish `ObjectNotFound` from denied access.

The command accepts both OCI Vault endpoint domains observed live:
GRU uses `.oraclecloud.com`, SFO uses `.oci.oraclecloud.com`. Existing DR
buckets and replication policies require explicitly reviewed IDs in config;
same-name replacements and unknown create responses cannot be adopted by
matching tags. Apply is incremental and reports successful IDs after later
failures for manual review and config pinning.

The independent prerequisite audit found TerraBase's whole-directory
restore, including `_system`, unfinished in `docs/backup.md` at inspected
TerraBase `origin/main` revision `263598b4`. Its current PITR endpoint requires
a registered source database and restores into a new database. The pinned
ts-go v1 SDK (`e534e7feb91f`) has no matching PITR or cold-recovery methods.
GRU's signed control state also cannot be imported as SFO desired state:
its logical identity and resource bindings belong to the serving source.

The preparation command is implemented and locally tested. Live apply,
cross-region key unwrap, destination secret/bootstrap recovery, full-cell
drill, monthly scheduling, and failure-alert delivery have **not** been
executed. Full-cell **RTO and RPO are unmeasured**. TS-641 remains incomplete.
See [the recovery runbook](../disaster-recovery.md).
