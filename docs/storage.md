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

## Opt-in features

Every feature below is off by default.

| Setting | Effect | Prerequisite |
|---|---|---|
| placement `auto_grow_volumes` | Grows a retained volume created under a smaller resource profile through the journaled `Fleet.ResizeRetainedVolume` (grow-only). | None. |
| host `managed_volume_online_grow` | The volume initializer rescans the device and grows the mounted filesystem: `EXT4_IOC_RESIZE_FS` for ext4, `xfs_growfs` for xfs. The device size is read from sysfs (`/sys/dev/block/<maj>:<min>/size`), because the pinned device descriptor is `O_PATH`. A grow is attempted when the device exceeds the filesystem's statfs size by at least 512 MiB, half of OCI's 1 GiB resize step, so every real resize triggers it. | ext4 growth needs `CAP_SYS_RESOURCE`, which the `terrascale-orchestrator-host-volume-init.service` bounding set grants. The setting gates growth only for the retired managed member path; the C# TerraBase data volume always grows (see [TerraBase runtime contract](terrabase-runtime-contract.md#data-volume)). |
| controller `storage_capacity.enabled` | Each controller publishes its boot root and JetStream StoreDir usage. The unused JetStream max-store reservation counts as used, and it is also subtracted from the node's boot headroom when the StoreDir is on the boot filesystem. Pressure is logged, and critical pressure is logged as an error. | None. |
| controller `volume_backup.enabled` | The leader keeps crash-consistent OCI volume backups of placed members' retained volumes: every `interval_hours`, with a FULL backup every `full_every` and INCREMENTAL backups otherwise. With `prune` set, `retain` must be at least `full_every`, so pruning never deletes the last FULL. | The controller dynamic group needs `manage volume-backups` in the compartment. |
| controller `volume_backup.prune` | Deletes owned AVAILABLE backups beyond `retain`. Before each delete it re-reads the backup's tags, source volume and state, and deletes with If-Match on the ETag. Owned backups of a volume that has left placement and no longer exists in OCI (404 or TERMINATED) are deleted once they are older than `orphan_retention_days` (default 30). Orphan retention runs only when every placement partition was readable on that pass. | `volume_backup.enabled`. |
| placement `reattach_on_host_loss` | A replacement host attempt takes over its lost predecessor's retained volume (see Reattach on host loss). | The lost-member replacement itself needs a `LostMemberEvidence` source. Roll every controller to this version first (new durable field). |

C# TerraBase member data volumes do not use the `volume_backup` runner:
`oci.MemberVolumes.Ensure` assigns each one the cell's OCI volume backup
policy (daily INCREMENTAL kept 7 days, weekly FULL kept 28 days), which OCI
runs itself. See [TerraBase runtime contract](terrabase-runtime-contract.md#backups).

After a C# member drains for scale-in, `oci.MemberVolumes.Retire` detaches
its exact recorded volume, tags it with the retired node name and time, and
keeps it. Reusing the name creates a fresh volume with a separate first-format
grant. Host replacement keeps the recorded volume. Retired volumes have no
automatic deletion; deleting one is a separate explicit, user-confirmed action.

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

With placement `reattach_on_host_loss`, a replacement host attempt (whose
member state records `previous_instance_id`) does not attach its retained
volume directly. Each placement tick runs one `failover.Reattacher` step:

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
