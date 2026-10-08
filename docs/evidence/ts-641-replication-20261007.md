# TS-641 live replication preparation, 2026-10-07

This follows the [pre-apply inspection](ts-641-preparation-20261007.md).
Preparation is partial. No full-cell recovery drill has run; RTO/RPO remain
unmeasured. Serving GRU has not been re-founded or used as a drill target.

## Verified retained resources

Successful create responses and matching readbacks identify these resources:

| Resource | Public ID | Observed state |
| --- | --- | --- |
| GRU scoped IAM policy | `ocid1.policy.oc1..aaaaaaaarqacwqum2uvqi2gkw6xvjpvz2g6m5wytsytm6rc5tstphihuaqha` | Active; corrected statements match the checked-in IAM plan. |
| SFO scoped IAM policy | `ocid1.policy.oc1..aaaaaaaas7tne544tq3oqgfpdjsr4cczbgyhwpr5qhqten4ip4uavpvm6wra` | Active; corrected statements match the checked-in IAM plan. |
| SFO backup mirror | `ocid1.bucket.oc1.us-sanjose-1.aaaaaaaawentiemlb37auxpbox42dvkczszzs7tlariqgzbfobu4psm3stzq` | `sfo-1-dr-gru-1-backup`; replication destination. |
| SFO backup seed | `ocid1.bucket.oc1.us-sanjose-1.aaaaaaaa4ibijpgbydhpzif2x4vyi5meqg3xjxh4w3exakiv7pwngonopbza` | `sfo-1-dr-gru-1-backup-seed`; versioning enabled. |
| GRU backup replication policy | `13d06611-adab-4443-afd0-4a57eaca82f3` | `TS-641-gru-1-backup`; active, targeting SFO. |

The GRU Vault has a `CREATED` replica in `us-sanjose-1`, with crypto endpoint
`https://ffvmfu2naagt6-crypto.kms.us-sanjose-1.oraclecloud.com`.
OCI exposes the original Vault ID, rather than a separate replica Vault OCID:
`ocid1.vault.oc1.sa-saopaulo-1.ffvmfu2naagt6.abtxeljr7ebplea4ua3memgthsupcfn3crg6d56vipsw7o2butchdrx3urmq`.
That state alone does not prove an existing backup key can be unwrapped there.

The two bucket IDs and replication-policy ID are pinned in
[the command config](../../deploy/oci-region/disaster-recovery.json).
A read-only run using that checked-in config passed after the pins were added.
IAM policy OCIDs are distinct from the Object Storage `policy_ids` map.

## Live failures and corrections

OCI rejected the initial source-region service grant with
`InsufficientServicePermissions`. Both receipt-owned IAM policies were updated
to the eight documented replication permissions, preserving other statements.
After propagation, OCI accepted the backup replication policy at
`2026-10-07T21:15:58Z`.

The first seed copy then failed on `probe/ts633` with `KmsHostNotFound`: its
request passed SFO's per-object KMS key header to GRU's Object Storage endpoint.
The corrected command inherits the admitted destination bucket key instead.
Focused race tests and independent review passed before the live retry.
The retry used clean pre-rebase source `ea811937`, SHA-256
`256d206ccd8a45a589a85f087c2faf5b4b6ba4e673f96fc03b0cbfed799261a1`.

## Bounded apply result

The corrected run began at `21:22:32 UTC`, with an enforced ten-minute
deadline. Host/T3 interruption lost its exec result and final copy report.
Its actual exit code, finish time and checksum-verified copy count are
**unknown**; an enforced timeout is not evidence that the timeout fired.
A local process audit at `21:58:45 UTC` found no surviving apply process.
No further apply or cloud mutation ran during receipt reconciliation.

Destination-only inventories at `21:57 UTC` observed:

| Bucket | Current objects | Current bytes |
| --- | ---: | ---: |
| `sfo-1-dr-gru-1-backup-seed` | 104 | 1,050,749,231 |
| `sfo-1-dr-gru-1-backup` | 2,386 | 473,133,156 |

These are object inventories, not a completed checksum-verified backfill or
a validated recovery point. The mirror continues receiving new source
objects. The last source policy inventory confirmed one active GRU backup
policy and no policies for GRU head or either SFO source bucket; the SFO
source Vault replica had not been created. Those source observations predate
the final destination-only reconciliation and are not fresh source readbacks.

Neither destination inventory contained `v1/keys/` objects. No existing-key
unwrap or authenticated backup-chunk proof passed; no generated keys were
substituted. Final receipt reconciliation made zero source-region calls.

Private local operational receipts are `/tmp/ts641-live-iam-receipts.json`,
`/tmp/ts641-live-summary.json`, and `/tmp/ts641-live-apply-*`; these are working
records, not a durable application report or a full recovery baseline.
No secret values or wrapped/plaintext key material are included here.

The [runbook](../disaster-recovery.md) lists the remaining cold-restore,
control-state rebinding, destination secrets/bootstrap, SFO rollback,
data-comparison and monthly-drill contracts. TS-641 remains incomplete.
