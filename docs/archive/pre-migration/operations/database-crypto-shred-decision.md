# Database crypto-shred: provider evidence and decision required

Status: proposal, 2026-09-05. No crypto-shred completion guarantee is implemented
or qualified. Local tombstones revoke service access; they are not irreversible
key destruction. GOAL.md requires owner approval of the physical deletion
completion promise, including backups and branches.

## What remains recoverable today

`databaseadmission.Record.Wrapped` persists regional DEK ciphertext in the
`database.admission` aggregate inside the global R3 `ORCH_LEADERS` stream.
`saveRecord` preserves that ciphertext across state changes. The authority
journal requires file storage, three replicas, and `MaxAge == 0`. Local catalogs,
older journal revisions, filesystem/block snapshots and exported control backups
can therefore retain a usable wrapper after every live host is tombstoned.
Anyone with that wrapper and regional KEK decrypt authority can recover the DEK.
A restored journal plus a usable shared KEK can undo access revocation.

Destroying one regional KEK today would also destroy access to unrelated live
databases. OCI has no per-ciphertext revocation/deletion API in the installed
KMS SDK. NATS `DeleteMsg` explicitly does not overwrite a message;
`SecureDeleteMsg` overwrites its message storage, but does not erase old filesystem,
block, cloud or exported snapshots. Neither API alone proves crypto-shred.

## Verified provider behavior

Official Oracle documentation retrieved on 2026-09-05:

- [Deleting a master encryption key](https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/managingkeys_topic-To_delete_a_key.htm):
  default deletion wait is 30 days; minimum is 7 days. `PENDING_DELETION`
  immediately prevents key use, but deletion can be cancelled. Scheduling is
  therefore access revocation, not irreversible completion.
- [Backing up and restoring vaults and keys](https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/backingupvaultsandkeys.htm):
  only virtual private vaults can be backed up as vaults; only HSM-protected
  master keys can be backed up as keys. **Software-protected master keys cannot
  be backed up through this feature.** HSM backups can restore keys after
  deletion, so changing protection type changes the deletion analysis.
- Installed official OCI Go SDK `v65.124.1`,
  `keymanagement/schedule_key_deletion_details.go` and
  `schedule_key_version_deletion_details.go`: both require deletion timestamps
  7–30 days after the request, defaulting to 30 days.
- That SDK's `KmsManagementClient.ScheduleKeyDeletion` and
  `ScheduleKeyVersionDeletion` documentation states a combined tenancy limit of
  10 provisioning write operations per second. Scheduling transitions to
  `PENDING_DELETION`; `CancelKeyDeletion` exists.
- The existing reconciler admits only `DEFAULT` vaults and software-protected
  AES-256 KEKs. The current deployment therefore fits the software-key backup
  restriction above. Imported copies, external escrow, Vault replication,
  provider retention after reported deletion, and any provider-internal backup
  behavior have not been qualified and must not be assumed absent.

Live OCI calls, current numeric key/version service limits, and current prices
were not verified. No pricing estimate or claim of instantaneous provider
irrecoverability follows from this document.

## Recommended architecture-preserving option: retire regional KEK versions

Batch eligible database deletions into a regional KEK-version retirement epoch.
This retains the ADR's regional KEK design and avoids one OCI master key per
customer database. It is a substantial global maintenance/recovery operation,
not a small change to the local tombstone API.

1. Fence admission, rotation, restore, branch and export writers against a durable
   regional wrapping epoch. Record deletion policy and legal/retention holds.
   Stop issuing leases for deleting scopes; collect tombstones from every host.
2. Inventory every DEK version and purpose that must remain recoverable and
   every historical regional KEK version that can unwrap any deleting scope.
   Include backup/export keys, retained branches, control-journal snapshots and
   replicas. Reject completion when that inventory is incomplete.
3. Create a fresh software-protected regional KEK version. Rewrap all surviving
   required DEKs under it, preserving their exact scope and purpose AAD. Do not
   rewrap deleting scopes. The installed crypto client has no re-encrypt
   operation; the concrete adapter currently requires a bounded locked-memory
   decrypt plus encrypt for each surviving wrapper. The old interface comment
   promising entirely in-Vault rewrapping is not evidence of such an API.
4. Commit new wrappers and require durable acknowledgements from all relevant
   hosts and control authorities. Publish a recovery checkpoint containing all
   surviving key versions before retiring old KEKs. Prove a restore using this
   checkpoint plus retained encrypted data artifacts. Old control snapshots
   alone will intentionally cease to be sufficient for key recovery.
5. Schedule deletion of *every* old regional KEK version that can unwrap the
   target database, only after step 4. This must cover all selected Regions and
   any Vault replicas; a remaining usable version leaves a recovery path.
   Incomplete survivor migration blocks scheduling. Cancellation or an unknown
   provider outcome blocks completion.
6. Keep deletion pending through the provider's minimum seven-day wait and
   verify authoritative final version state under an independently controlled
   deletion verifier. Do not equate one 404, denied IAM request, or scheduled
   timestamp with destruction. Account for imported/escrow/provider-backed
   copies if any were ever permitted. Wait for all leases to expire.
7. Then record the bounded provider-backed crypto-erasure result with its exact
   evidence and assumptions. Separately finish physical deletion of data,
   snapshots, exports, caches and backups under the approved retention promise.

Lease expiry is anchored to client request start. The local deletion operation
holds the same catalog lock as final lease transmission and conservatively
reports 1800 seconds after its deletion lock acquisition. This closes local
lease races; it does not replace the provider/version and replica obligations.

### Retention and recovery semantics

Deleting a wrapper from the current catalog is immediate access revocation.
Retaining an old wrapper in a snapshot is acceptable for *crypto-erasure* only
once every KEK version capable of decrypting it is irreversibly unavailable under
the provider-backed guarantee. Such snapshots still require physical deletion.
Surviving databases must recover through a retained, verified current key catalog
that maps their historical DEK versions to fresh regional KEK versions. That
catalog becomes a critical recovery dependency and must meet the R3/backup RPO.
No deletion schedule starts while legal holds or required survivor keys lack
qualified replacement wrappers.

### Cost and quota impact

For an epoch with N surviving regional wrappers, expect approximately N decrypt
and N encrypt operations, catalog distribution, and recovery verification. This
is O(all retained live wrappers in affected Regions), not O(deleted databases).
Each epoch adds a KEK version and schedules retirement of historical versions;
version limits and the documented combined 10 provisioning writes/second must
be respected. Batching amortizes work but delays deletion completion. No exact
financial cost can be stated until current OCI pricing and estate quotas are
measured. A seven-day minimum deletion wait plus migration/verification time rules
out an immediate crypto-shred promise under this option.

## Alternatives requiring a separate owner decision

**Per-database software OCI keys or an additional per-database envelope key:**
reduces deletion's survivor-rewrap blast radius, but adds OCI resource count,
provisioning load, inventory and an architectural layer absent from the ADR.
Every selected Region adds key resources; scheduling is still 7–30 days and
cancellable. Software-only, no imported/escrow copies and verified replica
handling remain necessary. Current key quotas and costs must be measured before
choosing it. A deletable secret holding another regional-KEK-wrapped value is
not sufficient if control snapshots retain that value.

**Tracked destruction of every wrapper copy without KEK retirement:** preserves
today's data path but makes completeness depend on enumerating and proving
physical removal from every NATS replica/history, host/catalog backup, block and
filesystem snapshot, export and external copy. No such complete inventory or
storage-erasure proof exists today. Ordinary purge, unlink, compaction, secure
message overwrite or tombstones do not provide it. Keep completion pending until
all retention and deletion evidence is satisfied.

## Decision requested

Approve development of the regional KEK-version retirement workflow and a
provider-delayed completion model, or choose the additional per-database key
architecture after quota/cost qualification. Until an option is implemented and
qualified, expose deletion as access revoked / cleanup pending and keep the
crypto-shred release gate unpassed. The public physical-deletion deadline remains
an owner decision after measured retention and provider behavior are available.
