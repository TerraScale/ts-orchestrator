# Storage

`internal/storage` owns retained-volume policy for TerraBase members. OCI
mutation authority (journal, ownership, epoch fencing, ETags) stays in
`internal/oci`; the storage slice composes it and never adopts a resource
from tags alone.

| Package | Purpose |
|---|---|
| `storage/lifecycle` | Pure volume state machine with deadlines and `stuck`/`held` phases. Placement uses it to hold an attachment stuck ATTACHING (default 10 minutes) with a remediation instead of waiting forever. |
| `storage/hostvolume` | Host-side primitives for the root volume initializer: hardened mount flags, ext4/xfs format commands, online grow. |
| `storage/capacity` | statfs collector, the TTL'd `TS_STORAGE_USAGE` KV bucket, and pressure signals for placement and autoscaling. |
| `storage/backup` | OCI volume backup policy, planner and leader-only runner with fenced retention. |
| `storage/failover` | Core for reattaching a volume after its host is lost. It requires proof that the old instance is TERMINATED. |

## Mounts

Managed volumes are mounted `nosuid,nodev,noexec,noatime`. ext4 volumes also
use `errors=remount-ro`. The initializer reads the per-mount flags back
before it completes the volume layout. TerraBase runs from the managed runtime
root, not from the volume. The volume holds only `data/`, `replication/` and
the claim file, so it needs no exec, set-id or device nodes. A mount made by
an older initializer is bind-remounted with the hardened flags the next time
the initializer touches it. This is best effort and failures are logged.

A signed `xfs` pin is formatted with `mkfs.xfs -m uuid=<pin>`, which needs
`xfsprogs` on the host image.

## Opt-in features

Every feature below is off by default.

| Setting | Effect | Prerequisite |
|---|---|---|
| placement `auto_grow_volumes` | Grows a retained volume created under a smaller resource profile through the journaled `Fleet.ResizeRetainedVolume` (grow-only). | None. |
| host `managed_volume_online_grow` | The volume initializer rescans the device and grows the mounted filesystem: `EXT4_IOC_RESIZE_FS` for ext4, `xfs_growfs` for xfs. | ext4 growth needs `CAP_SYS_RESOURCE` in the `terrascale-orchestrator-host-volume-init.service` bounding set (operator drop-in). The default unit does not grant it. |
| controller `storage_capacity.enabled` | Each controller publishes its boot root and JetStream StoreDir usage. The unused JetStream max-store reservation counts as used. Pressure is logged, and critical pressure is logged as an error. | None. |
| controller `volume_backup.enabled` | The leader keeps crash-consistent OCI volume backups of placed members' retained volumes: every `interval_hours`, with a FULL backup every `full_every` and INCREMENTAL backups otherwise. | The controller dynamic group needs `manage volume-backups` in the compartment. |
| controller `volume_backup.prune` | Deletes owned AVAILABLE backups beyond `retain`. Before each delete it re-reads the backup's tags, source volume and state, and deletes with If-Match on the ETag. | `volume_backup.enabled`. |
| `failover.Config.Enabled` | Reattach core only. It is not wired yet. | Follow-up OCI fleet support (see below). |

## Resize and ownership

A `volume-resize` operation is keyed by volume and target size. Its intent
records the predecessor size and ETag. One If-Match `UpdateVolume` changes
both the size and the `terrascale-volume-size-gib` tag. The confirmed result
advances the volume ownership record by CAS. If that ownership record is lost,
it is rebuilt from the confirmed create plus the confirmed resize. A size
change made out of band (for example in the OCI console without the tag)
still makes the volume foreign, by design.

## Follow-ups

- Host-side usage of managed mounts: hosts may publish only their
  observation subject. Carry usage in the host observation and let the
  controller republish it.
- Reattach wiring in `internal/oci`: a journaled detach for an attachment of
  a TERMINATED instance, attach over DETACHED attachment history, and a
  mount-existing (never format) permit in `InspectVolumeInitialization`.
- A signed grow verb or a desired volume size field so a live member's
  filesystem grows without waiting for the next initializer run.
