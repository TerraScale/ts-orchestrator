# Storage

`internal/storage` owns retained-volume policy for TerraBase members. OCI
mutation authority (journal, ownership, epoch fencing, ETags) stays in
`internal/oci`; the storage slice composes it and never adopts a resource
from tags alone.

| Package | Purpose |
|---|---|
| `storage/lifecycle` | Pure volume state machine with deadlines and `stuck`/`held` phases. Placement uses it to hold an attachment stuck ATTACHING (default 10 minutes) with a remediation instead of waiting forever. |
| `storage/hostvolume` | Host-side primitives for the root volume initializer and `terrabase restore-check`: hardened mount flags, ext4/xfs format commands, online grow, boot-disk and mounted-device checks. |
| `storage/capacity` | statfs collector, the TTL'd `TS_STORAGE_USAGE` KV bucket, and pressure signals for placement and autoscaling. |
| `storage/backup` | OCI volume backup policy, planner and leader-only runner with fenced retention. |
| `storage/failover` | Reattaches a volume after its host is lost. It requires proof that the old instance is TERMINATED. Placement drives it for replacement host attempts through the OCI boundary in `failover/oci.go`. |

## Mounts

Managed volumes are mounted `nosuid,nodev,noexec,noatime`. ext4 volumes also
use `errors=remount-ro`. The initializer reads the per-mount flags back
before it completes the volume layout. TerraBase runs from the managed runtime
root, not from the volume. The volume holds only `data/`, `replication/` and
the claim file, so it needs no exec, set-id or device nodes. A mount made by
an older initializer is bind-remounted with the hardened flags the next time
the initializer touches it, including a mount that has the three security
flags but lacks `noatime`. This is best effort and failures are logged.

A signed `xfs` pin is formatted with `mkfs.xfs -m uuid=<pin>`, which needs
`xfsprogs` on the host image.

## Fixed storage policy

Every storage feature must always be available, with fixed correct limits and
automatic credential delivery. Ownership, complete observations, retention and
backup-chain integrity checks remain required for any deletion.

Capacity collection, placement volume backups and pruning, volume growth,
and reattachment have no activation settings. Removed config members are
rejected, including the former `storage_capacity` and `volume_backup` blocks.

| Behavior | Fixed policy and required evidence |
|---|---|
| Controller capacity | Every controller measures its boot root and JetStream StoreDir every 30 seconds, with a two-minute record TTL. Pressure thresholds are 70%/85%/95%, with floors of 1 GiB and 1,024 free inodes. Unused JetStream reservation counts against headroom. |
| Placement volume backups | Every regional managed leader evaluates every 15 minutes and backs up each placed retained volume daily. The first backup and every seventh successor are FULL; others are INCREMENTAL. The newest seven AVAILABLE backups survive pruning. The controller's instance principal needs `manage volume-backups` in its admitted compartment. |
| Backup pruning | Each eligible delete rechecks exact ownership, source volume, AVAILABLE state and ETag. Every evaluation records a scope-verified TERMINATED source for owned orphan backups, including those younger than 30 days, in the replicated non-expiring OCI journal. Terminal reconciliation also persists exact TERMINATED reads during inventory verification and deletion readback; a failed proof write keeps teardown pending for retry. Read-only status never creates proof. After 30 days that durable proof authorizes pruning even after OCI purges the source, only with a complete placement inventory. A 404 without prior proof, a mismatched scope or a journal failure holds deletion. |
| Grow and reattach | Placement grows an owned undersized volume during preparation. A replacement with a durable predecessor uses the fenced reattachment sequence below. The host initializer always attempts grow on its verified exclusive mount; growth errors are logged while that mount remains usable. |

Fixed retention applies to existing controller-owned AVAILABLE backups as well
as new backups. The next successful evaluation can delete older recovery
points kept by previous settings: placed sources keep the newest seven,
and proven-terminated sources become eligible after 30 days from backup creation.
Every eligible deletion checks exact ownership, current authority and a fresh
ETag; orphan deletion also requires durable source-termination proof.

Filesystem growth rescans the pinned device, reads its size from sysfs and
uses `EXT4_IOC_RESIZE_FS` for ext4 or `xfs_growfs` for xfs. Growth begins when
the device exceeds the filesystem by at least 512 MiB. The volume initializer
unit grants `CAP_SYS_RESOURCE` for ext4 growth. Placement runs every five
seconds; its file carries only `environment`, `member_role` and `resources`.

Signed production manifests bind all three managed regional inputs. Removing
the unmanaged startup path remains part of the discovery slice.
Capacity signals are collected, but a production placement pressure consumer
and a lost-member evidence source still need wiring. Reattachment cannot bypass
that missing replication/quorum/writer-stop evidence.

Static C# TerraBase member data volumes use the separate mandatory OCI policy:
`oci.MemberVolumes.Ensure` assigns daily INCREMENTAL backups kept seven days
and weekly FULL backups kept 28 days. OCI executes those schedules itself.
See [TerraBase runtime contract](terrabase-runtime-contract.md#backups).

After a C# member drains for scale-in, `oci.MemberVolumes.Retire` detaches
its exact recorded volume, tags it with the retired node name and time, and
keeps it. Reusing the name creates a fresh volume with a separate first-format
grant. Host replacement keeps the recorded volume. Retired volumes have no
automatic deletion; deleting one is a separate explicit, user-confirmed action.

## Artifact store collection

The delivery artifact store (`TS_ARTIFACTS`) holds every uploaded release
binary under a byte quota. Once full, uploads fail with
`delivery artifact store quota is full`. Each minute the authority leader
collects it (`internal/delivery/artifact_gc.go`) and keeps:

- every digest a committed host desired names, withdrawn targets included;
- every digest an undecided delivery names;
- per role and environment, the rollback target: the newest delivered digest
  (accepted or held delivery operation) not in use. A role nothing runs
  keeps its two newest delivered digests; a role no delivery released (for
  example orchestrator binaries for `ts-orch rollout`) its two newest
  admissions;
- anything whose metadata was written in the last hour: uploaded, admitted
  or named by a desired commit, which each touch it.

It deletes every other object and purges chunks no object references once
they are idle for 20 minutes: an upload ends within 15, so those belong to an
interrupted upload whose own cleanup the operator was not allowed to purge.
The collector reads the objects' metadata before any reference, and a
reference read error skips the pass. Each deletion is a compare-and-set on
the metadata it read (`artifact.DeleteIfUnchanged`), and every desired
commit and admission first republishes the metadata the same way
(`artifact.Touch`). A reference made after the collector chose an object
therefore refuses its deletion on the server, even from a former leader
that resumes late; a commit after the deletion finds the object gone. The
leader logs `artifact store collected` with the deleted digests and purged
subjects. Admission records stay; re-push a deleted binary with
`operator artifact-push` (or the release command) before deploying it again.

The quota is `controller.artifact_store_max_bytes` (default 2 GiB; rendered
controller configs set 512 MiB) until a cell spec sets
[`artifact_store`](cell-spec.md#model). The leader applies the spec's quota
within a minute. Every controller refuses a quota above its embedded NATS
`store_max_bytes` less 3 GiB for control state and host metric history at
startup. Cell-spec validation requires 3.5 GiB headroom, or 4 GiB with
`machines_api`. The leader raises the quota
only while the NATS store's disk has room for the store to fill. A
controller restart never shrinks a larger quota already in force.

## Resize and ownership

A `volume-resize` operation is keyed by volume, target size and attempt.
Attempt 1 keeps the original `<volume>/<size>` key; later attempts use
`<volume>/<size>/attempt-<n>`, up to 8. Its intent records the predecessor
size and ETag. One If-Match `UpdateVolume` changes both the size and the
`terrascale-volume-size-gib` tag. The confirmed result advances the volume
ownership record by CAS. If that ownership record is lost, it is rebuilt
from the confirmed create plus a confirmed attempt of the resize. A size
change made out of band (for example in the OCI console without the tag)
still makes the volume foreign, by design.

A new attempt starts only when the previous attempt of the same target never
confirmed, the volume is still below the target, and its ETag no longer
matches the attempt's If-Match ETag, so that request can never land as
journaled. Before attempts existed, such a same-size retry held with
`ErrStaleETag` (#133, finding 11583 item 2). With the ETag unchanged an
unknown attempt is retried on its own key, as before. A volume whose ETag
moves under all 8 attempts holds with `ErrStaleETag`.

## Reattach on host loss

A replacement host attempt whose member state records `previous_instance_id`
always uses fenced reattachment for its retained volume. Each placement tick runs one `failover.Reattacher` step:

1. Prove the old instance fenced: OCI must report it `TERMINATED`. A
   STOPPED, TERMINATING, missing (404) or unreachable instance holds the
   member; the attach deadline still reports a stall. An observed
   non-TERMINATED state is a normal hold; a failed lifecycle lookup
   (`failover.ErrFenceUnobserved`: authorization, network, cancellation or a
   purged instance) also holds but is reported as a controller error.
2. Detach a live attachment of the old instance through
   `Fleet.DetachFencedAttachment`: a journaled `volume-detach` (same key as
   the evidence-driven detach of that attachment fence) whose fence is
   re-read after the authority guard, right before the effect. A detach
   that does not reach DETACHED within the settle window is recorded
   Unknown; terminal discovery treats a detach whose exact attachment is
   now DETACHED or gone as settled.
3. Wait until OCI reports that attachment DETACHED.
4. Attach to the replacement with `AllowDetachedHistory`: DETACHED records
   no longer hold the attach. Any other live attachment still holds it, and
   a live attachment on an unrelated instance holds the reattach for an
   operator.
5. Record a mount-existing permit (`volume-mount-permit.*` in the OCI
   journal bucket, immutable) once the replacement holds the volume's only
   live attachment and it is journal-owned.

Each step is guarded against the tick's authority epoch and bound to it
(`Reattacher.ExpectedEpoch`), so member state read under one epoch never
drives a detach or attach under a later one. Placement also holds one
workload effect at that epoch for the whole step in a shared effect context
(`authority.WithActiveWorkloadEffectContext`); every nested OCI effect joins
it, and a nested effect under another epoch is fenced.

`InspectVolumeInitialization` admits a volume with DETACHED attachment
history only when that permit names exactly the pinned attachment, workload
and replacement instance, and the pinned attachment is the only live one.
It then answers without format authority: the replacement mounts the
existing filesystem and never formats it. A replacement whose volume was
never formatted therefore fails closed at initialization.

Each fenced detach, replacement attach and mount permit is recorded in the
decision journal (`volume_reattached`, rule
`storage.reattach_on_host_loss`).

## Configuration snapshots

`internal/kvsnapshot` keeps the configuration KV buckets
(`kvsnapshot.Buckets`: `TS_SERVICE_SET`, `TS_TRUST_ROOTS`, `TS_HOST_ENROLLMENT`,
`TS_ROLLOUTS`, `TS_OCI_DESIRED`, `TS_APPS`, `TS_MACHINES`, `TS_VOLUMES`) in OCI Object Storage, so that a controller set rebuilt
with empty JetStream stores gets them back without any re-signing.

The controller's instance principal discovers the tenancy namespace. Its
catalog region determines the existing regional head bucket, such as
`gru-1-head`; the snapshot location and cadence have no configuration block.
Before use, the uploader verifies the returned bucket name and namespace,
enabled version history, and a managed default KMS key. A missing dependency or
refused grant is an error. The controller needs namespace discovery and read
access to that bucket's metadata, plus object read, create and overwrite on
`kv-snapshot/v1/*`. Snapshot writes use the bucket's default encryption key.

**Snapshots.** Every thirty seconds the authority leader reads each bucket's
stream and, if its last sequence moved, writes the latest value of every key
to `kv-snapshot/v1/<cell>/<bucket>.json` with an ETag compare-and-swap.
The object records the stream's creation time and last sequence. A writer
never replaces a snapshot of a newer stream or a higher sequence of the same
stream, so a deposed leader or an old cell cannot roll it back. Only a changed
bucket is uploaded; an unchanged bucket is checked against storage so an
unreadable or missing copy cannot appear healthy. There is no pause control.
With healthy dependencies and a short upload, a change reaches Object Storage
within about thirty seconds; changes made after the latest successful snapshot
are lost if every controller loses its store.

**Restore.** After the cluster forms and before authority or any store
opens, the controller reads the plan in `TS_KV_RESTORE`. A complete plan
means the cell has already restored, so an ordinary restart needs no OCI.
Without a plan, a cell whose `TS_CONTROL_LOG` already holds records kept its
JetStream state: it records an empty plan without reading OCI, so a live cell never restores stale snapshots over its retained state. In a new or rebuilt cell,
the first controller restores each bucket that has a snapshot and whose
stream is missing or was never written. Every controller
that boots while the plan runs finishes it first. A value is written only if
its key never had a revision in this cell (`Update(key, value, 0)`), so a
live update or delete always wins and a completed plan never runs again.
Values are restored byte for byte. Signed values (the cell spec) are verified
by their owners as before. A restored bucket gets its recorded description,
history, value limit and compression with the cell's replica count, never a
TTL or byte limit, until its owner opens it with its own configuration.
Each restore attempt is bounded at two minutes and retried in place, with
the broker still serving the other controllers' quorum.

**Trust.** Only `ObjectNotFound` means "no snapshot"; a missing bucket or a
refused grant fails the boot. A snapshot must name this cell and bucket and
hold sorted, valid keys within the recorded value limit. The snapshot itself
is not signed. Write access to the prefix steers what a rebuilt cell starts
with (for example its desired OCI resources, or a rollout snapshot without a
known-bad record), so it is as trusted as a controller. Grant it only to the
controller dynamic group, and keep that group matching only the controller
instances; for `gru-1` it matches every instance in `gru-1-control`, the
same boundary as the bootstrap ledger prefixes.

**Not covered.** `TS_CONTROL_LOG` (authority leases, the operation journal,
placement intents) and the KV state bound to its epochs (`TS_OCI_OPERATIONS`,
`TS_PLACEMENT_STATE`, `TS_HOST_STATE`, `TS_DELIVERY_*`) are not snapshotted: a rebuilt cell starts its
authority epochs afresh, so restoring them needs epoch continuity first.

## Follow-ups

- Host-side usage of managed mounts: hosts may publish only their
  observation subject. Carry usage in `memberstatus`, republish it from the
  controller, feed `SignalSource` and `NodeHeadroomBytes` into placement
  instead of the configured `DiskBytes`, and cordon on critical JetStream
  pressure.
- A per-member desired volume size and a signed grow request to the host
  initializer, so a live member's filesystem grows without waiting for the
  next initializer run.
- Reattach after the old instance has been purged from OCI (404) needs a
  separate proof; today it holds.
