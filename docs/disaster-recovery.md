# Full-cell disaster recovery (TS-641)

Prepare cross-region recovery copies with the existing Go binary:

```sh
ts-orch disaster-recovery replicate --config deploy/oci-region/disaster-recovery.json
ts-orch disaster-recovery replicate --config deploy/oci-region/disaster-recovery.json --apply
```

The first command reads OCI and prints the plan. The second creates missing
Object Storage buckets, replication policies and Vault key replicas, and
backfills existing objects with checksum readback. Both pin the actual control
compartments, Vaults and regional bucket keys. All IDs in the config were read
from OCI on 2026-10-07; it contains no credentials. An existing resource with
different ownership or encryption is refused. There is no deletion path.

Capture the JSON output of apply. Before another run, review its
`mirror_bucket_id` and `seed_bucket_id` and pin them in the destination
region's `bucket_ids` map by bucket name. Pin `policy_id` in the source
region's `policy_ids` map by policy name (`TS-641-<source-bucket>`). Existing
resources require these IDs as well as matching settings; names and tags
alone do not authorize adoption. Successful create IDs are included even
when a later step fails. Missing pinned resources and same-name replacements
are refused. A lost create response leaves the resource unowned: inspect it
manually and explicitly record its reviewed ID before resuming. Apply is
incremental; failures do not delete earlier successful resources or policies.
OCI's copy and policy APIs address destination buckets by name. Identity
checks run before policy creation, before each seed copy and before success,
but they cannot make an OCI request atomic with its preceding read. Serialize
preparation against administrative bucket replacement and policy changes.

**Recovery is not implemented yet.** This command prepares copies; it does not
rebuild a cell, restore TerraBase or ts-auth, or measure RTO/RPO. TS-641 stays
open until the cold-restore service contract (TerraBase: TS-743) and the sjc
drill below pass.
Never use quorum recovery or a regional founding attempt to run this drill
against serving gru-1.

## Copy layout and encryption

OCI makes a replication destination read-only. Each active regional bucket
therefore gets a dedicated mirror in the other region:

| Source | Continuous mirror | Historical seed |
| --- | --- | --- |
| gru-1-backup | sjc-1-dr-gru-1-backup | sjc-1-dr-gru-1-backup-seed |
| gru-1-head | sjc-1-dr-gru-1-head | sjc-1-dr-gru-1-head-seed |
| sjc-1-backup | gru-1-dr-sjc-1-backup | gru-1-dr-sjc-1-backup-seed |
| sjc-1-head | gru-1-dr-sjc-1-head | gru-1-dr-sjc-1-head-seed |

OCI only replicates objects uploaded **after** policy creation. The command
activates the policy first, then enumerates all current source objects and
copies each one the mirror lacks into a separate writable, versioned seed
bucket. An object whose mirror copy already matches its size and checksum
is counted in `mirrored` instead of copied again; a differing mirror version
still gets the source version seeded. Each inventory page is copied by 16
workers. The policy and read-only mirror identity are checked again before
success. Source ETag and destination CAS
conditions prevent a changed source or concurrent backfill from silently
winning; every completed copy must match its size and checksum (ordinary MD5,
or streamed SHA-256 for missing/multipart checksums). Object names
stay identical because TerraBase's envelope encryption binds them to the key
name. Interrupted runs resume by comparing checksums. A source change during
copy fails the command; retry reads its new version. Newly added objects go
to the mirror even if pagination misses them. This is a current-object copy,
not a copy of old versions or previously deleted objects.

A recovery reader must inspect both inventories and choose generations at
the common PITR point, using validated snapshot timestamps, journal coverage
and checksums. Bucket location and destination modification time do not
establish which generation is newer: asynchronous replication can leave V1
in the mirror while a seed pass has already copied V2. The future recovery
reader must test that case and fail when a complete, consistent recovery
point cannot be established. No such reader is implemented by this command.

A mirror alone can lack wrapped data keys and snapshots that predate its
policy. Seeds preserve only versions actually copied by a seed pass. An
object created later and overwritten or deleted before another pass has no
historical seed copy; the unversioned mirror can lose it too. Source deletes
and overwrites replicate to the mirror, and objects the mirror already held
are not seeded: the source bucket's retention rule (35 days on
`gru-1-backup`) is their only delete protection. Archival
capture of subsequent generations is required before claiming a durable
recovery baseline. Seed retention and garbage collection must be bound to
that validated baseline before monthly drills are enabled; this command
does not prune seeds. Do not configure a service to read only the mirror
and claim a full backup.

Mirrors have neither versioning nor retention rules, both unsupported for
OCI replication destinations. Seeds have versioning enabled. All copies
use the **destination region's bucket encryption key**, so Object Storage
readback does not depend on the lost region's bucket key endpoint.
Backfill inherits that admitted bucket key instead of passing it to the
source endpoint in a per-object KMS header; OCI rejected the cross-region
header with `KmsHostNotFound`. See [Object Storage encryption](https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/encryption.htm).

TerraBase additionally wraps per-project and `_system` data keys with its
backup master key. Both regional Vaults support replication (`GetVault`
reported `isVaultReplicable=true`). The command creates/reuses their Vault
replicas and reports the remote cryptographic endpoint. Recovery must use
the original key ID at that endpoint and prove it unwraps an existing copied
data key with the source endpoint unreachable. A newly generated key cannot
decrypt existing backups. That proof passed for GRU on 2026-10-08 (see the
evidence below). OCI lists each replica endpoint in the source region's
domain, but each region resolves only its own: us-sanjose-1 under
`oci.oraclecloud.com`, sa-saopaulo-1 under `oraclecloud.com`. Use the
destination region's form of the listed host, e.g.
`ffvmfu2naagt6-crypto.kms.us-sanjose-1.oci.oraclecloud.com`. Key replication does **not** replicate Vault
secrets: bootstrap credentials, role secret refs, ts-auth signing/master
keys, S3 credentials and the KMS API signing credential need separate secret
replication and a destination-only read test.

See OCI's [replication rules](https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/usingreplication.htm),
[versioning interactions](https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/usingversioning.htm),
[retention interactions](https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/usingretentionrules.htm)
and [Vault replication](https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/replicatingvaults.htm).

## IAM before apply

The reviewed [IAM apply plan](../deploy/oci-region/disaster-recovery-iam.json)
names `gru-1-disaster-recovery` and `sjc-1-disaster-recovery`, their pinned
control compartments and their exact statements. These are separate IAM
policies; `policy_ids` in the command config identifies Object Storage
replication policies. Inspect for existing names before creating either IAM
policy, capture its successful create OCID, and verify that OCID, compartment,
name and statements on readback. Record changed IAM IDs with apply evidence.

OCI validates all eight documented replication permissions for the
source-region Object Storage service principal on both the source buckets
and the destination mirror/seed buckets: bucket read/update and object
read/inspect/create/overwrite/restore/delete. A source grant restricted to
read permissions returned `InsufficientServicePermissions` during live
policy creation. These service grants support native replication; the
preparation command reads source objects and writes only destination copies.
Grant those exact bucket names in their respective control compartments,
not `manage object-family in tenancy`. Both regional Object Storage
principals need use of the respective bucket keys. The operator
needs bucket create/read, replication-policy create/read, object list/read,
copy work-request read, and Vault replica create/read. OCI's Vault service
needs the replica-management grant described in its documentation, scoped
to the two control compartments rather than the tenancy.

The command does not edit IAM. An authorization failure must fail the
operation; a 404 other than `BucketNotFound`/`ObjectNotFound` never means
there is no bucket/object. Controller/host grants for future recovery must
allow only their destination copies and destination secret bundles.

## Required cold-restore contract

Existing configuration snapshots carry the original cell identity and signed
values. `kvsnapshot.Restore` accepts only its own cell and runs before stores
open on a fresh JetStream lineage. Copying GRU's signed spec and OCI resource
IDs into SJC's running KV would target GRU resources or fail signature/cell
checks. Do not strip signatures or rewrite OCIDs to make it pass.

The complete path needs these reviewed contracts:

1. Destination recovery admission binds the sjc-1 cell and its pinned
   instances, refuses gru-1 as a drill target, fences sjc placement and edge,
   and retains a tested rollback of sjc's pre-drill state. Source operations
   are read-only. No new nodes, scratch cell or serving gru-1 re-found.
2. A bounded Object Storage recovery bundle includes the bootstrap
   configuration, original KV snapshots, signed cell spec, trust chain and
   secret **references**. A root-authorized import maps the recovered logical
   control state to SJC without adopting GRU instances, volumes or authority
   leases. KV snapshot copies alone are not a bootstrap bundle.
3. TerraBase owns a cold restore of `_system` plus **every** database at a
   common PITR second from seed + mirror, with the original identities. It
   needs copied keys and the remote KMS endpoint; it must work without the
   source catalog, API, NATS or Vault. Expose that operation through ts-go.
   The currently pinned ts-go v1 SDK has no PITR/backup methods. TerraBase's
   existing `point-in-time/restore` API requires a live source database's
   catalog registration and creates a new database; it cannot rebuild a lost
   catalog. Legacy `Backups.RestoreBackup` methods target a retired contract
   and must not be used to bypass the current SDK boundary.
4. Restore ts-auth's TerraBase data and replicated secrets after database
   restore, then verify native ts-auth SDK login/token issuance and regional
   serving. No service may copy or edit another service's application records
   directly.

The existing scratch-host volume restore/check commands test another
failure mode. Their guard intentionally refuses orchestrator hosts; do not
remove it to run this drill on sjc's serving hosts.

## Drill acceptance and monthly execution

Keep the monthly **destructive drill disabled** until the contracts above and
sjc rollback are qualified. A placeholder command, a source-dependent PITR
restore, or a health check is not a full-cell drill.

1. Bind and verify source gru-1 and target sjc-1. Inventory every source
   database through ts-go; retain its identity, chosen PITR point and source
   data checksums. Use a common point available in both regional copies,
   including `_system` and ts-auth. Record backup and KV snapshot ages.
2. Start a monotonic timer at drill admission. Make source-region API, NATS,
   Object Storage and KMS unavailable to the destination recovery process.
   Execute control-state recovery, every database restore, then ts-auth in
   that order using existing sjc resources. Never alter serving gru-1.
3. Compare restored data at the selected point through SDKs against the
   retained source checksums. Verify all expected identities, ts-auth token
   issuance and sjc's serving endpoints. Stop the RTO timer only then.
4. Persist the report in TerraBase and retain its record ID and measured
   numbers in the repository's recovery evidence. RTO is
   admission-to-verified-serving duration. RPO is the gap between the last
   acknowledged source write at the simulated
   loss boundary and the last recovered write; report actual missing
   writes separately. Never label OCI policy lag as measured data RPO.
5. Restore sjc's prior state and verify serving. Once this passes, schedule
   the same destination-bound command monthly with exclusive admission,
   a finite deadline and alert delivery through the existing monitoring
   path on failure, missing result, checksum mismatch or missed schedule.

No live full-cell drill has run, and no measured full-cell RTO/RPO exists.
Record the first result here with its retained report before claiming this outcome.

The [2026-10-07 live preparation record](evidence/ts-641-replication-20261007.md)
tracks the scoped IAM changes, retained backup mirror/seed and policy IDs,
GRU Vault replica, copy-request corrections and bounded backfill result.
The [2026-10-08 record](evidence/ts-641-replication-20261008.md) completes
all four copy directions and both Vault replicas, and proves a copied GRU
data key unwraps in SJC. Copies alone do not establish a recovery point.
