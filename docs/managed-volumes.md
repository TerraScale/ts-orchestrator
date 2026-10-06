# Managed volumes

TerraBase members keep their SQLite data on the boot volume today, so a
relaunched VM loses it. Managed volumes are orchestrator-owned OCI block
volumes in the style of Fly volumes: a volume belongs to an app, lives in one
availability domain, and is mounted by at most one machine. Package
[`internal/volume`](../internal/volume) owns the model. This note is the
design for TS-567; the [slices](#slices) section says what exists.

## Model

A volume is one record in the replicated KV bucket `TS_VOLUMES`, keyed by its
ID (`vol_` and 16 base32 characters). The bucket is in
[KV snapshots](storage.md#configuration-snapshots), so a rebuilt cell still
knows its volumes.

| Field | Owner | Meaning |
| --- | --- | --- |
| `id`, `app`, `name`, `region`, `zone`, `created_at` | creator, immutable | `zone` is the OCI availability domain, chosen when the volume is created. Names are not unique: like Fly, an app scales by giving several machines a volume of the same name. |
| `size_gb` | API, grow only | Desired size, 50 to 32768 GB (OCI's limits). |
| `vpus_per_gb` | API | OCI performance tier: 0 (Lower Cost), 10 (Balanced, the default), 20 to 120. |
| `snapshot_retention` | API | Days of daily snapshots, 1 to 60 (default 5), as in Fly. |
| `machine_id` | scheduler | The machine that may mount the volume. |
| `destroy_requested_at` | API, final | Starts the destroy. |
| `status` | reconciler | `state`, the `epoch` of the writing leader, the OCI volume `ocid`, the confirmed `size_gb`, the machine it is attached to, and a message. |

The store checks every update against the stored record by compare-and-set
on the KV revision. It refuses:

- a record whose body does not match its key or cell;
- a change to an immutable field, a shrink, or a new OCI volume for the
  record;
- a claim that moves a volume from one machine straight to another, a claim
  of a destroying volume, and a destroy of a claimed volume (also within one
  write);
- a status written under an older authority epoch than the stored one, so a
  deposed leader cannot overwrite a newer observation;
- any change to a destroyed volume.

States are `creating`, `created`, `pending_destroy`, `destroyed` and
`failed`. Growing and attaching show in the spec and status fields and need
no states of their own. The reconciler slice adds the attachment ID,
instance and device to `status`: a host can hold several volumes, so the
fixed member device `/dev/oracleoci/oraclevdb` is not enough.

## Placement

A machine mounts a volume with `{"volume": "vol_...", "path": "/data"}`, the
Fly machine config shape. Like Fly, a machine mounts at most one volume.
`Store.Zone` checks the mount and returns the availability domain the
machine must run in: the volume must belong to the machine's app, be
unclaimed or claimed by that machine, and be neither destroying nor failed;
the path must be absolute, clean and outside `/dev`, `/proc`, `/run` and
`/sys`. The scheduler then picks a host in that zone and claims the volume
with `Store.Claim`. A claim moves only between "no machine" and one
machine, and a stale `Release` from a former machine changes nothing.

GRU has one availability domain, so a volume's zone never spreads an app;
members spread over fault domains of their hosts, which the scheduler picks.

## Reconciler

The authority leader reconciles `TS_VOLUMES` against OCI with the volume and
attachment calls of [`internal/oci`](../internal/oci), which already
creates, attaches, grows, backs up, restores and reattaches retained
volumes. Every effect is fenced to the leader's epoch, and the status it
writes carries that epoch.

**Ownership.** The record is written before any OCI effect, so it is the
durable intent of the create. The create's retry token is derived from the
cell and the volume ID, and the volume carries the cell's ownership tags and
the volume ID. The reconciler binds an OCI volume to a record only when:

- the record has no OCID yet and exactly one volume in the compartment
  carries this cell's tags and this volume ID, created after the record's
  `created_at`. IDs are random, so no volume can be planted for a record in
  advance. No match means create; several matches mean `failed`;
- or an operator adopts an existing volume by its exact OCID, for example a
  member's `<member>-data` volume from `ts-orch terrabase data-volume`. The
  adoption tags it with the volume ID first.

It acts on a recorded OCID only while that volume still carries those tags,
so a hand-written record, or one restored from a KV snapshot, cannot point
it at another volume. After a rebuild, the restored records are bound again
by the same rules.

- **Create.** In the record's zone, with the cell's KMS key (the regional
  Vault key; no volume is created without one), the record's VPUs and the
  backup policy for its retention. Policies are created when a retention is
  first used.
- **Attach.** Paravirtualized, read-write, not shareable, with in-transit
  encryption, at a free consistent device path, to the claimed machine's
  host.
- **Detach.** Only after the host proves the machine stopped and unmounted the
  volume, or OCI reports the old instance `TERMINATED`
  ([reattach on host loss](storage.md#reattach-on-host-loss)).
- **Grow.** One If-Match `UpdateVolume`; the host grows the filesystem online.
- **Destroy.** Refused while a machine holds the volume, and held while a
  clone of it is still being created. The reconciler detaches it, takes a
  final snapshot, deletes the OCI volume and purges the record once OCI
  confirms the delete. Snapshots stay until their retention ends, so they
  are the undo.

## Snapshots, restore, fork and move

Snapshots are OCI volume backups recorded with the app and volume they came
from; a restore or fork names a snapshot or volume of the same app only, so
one app or tenant never reads another's data. The reconciler checks the
source again before it acts. A fork clones a volume in its zone
(crash-consistent, which SQLite's WAL makes restorable). A forked or
restored TerraBase volume carries its source member's claim file and
`replication/` state, so the new member resets them before it starts and
catches up through TS-561 replication. A clone also keeps its source's
filesystem UUID, so the host gives it a new UUID on its first mount and
mounts by device path. Moving to another zone is a snapshot, a restore in
that zone and a switch.

## Host

The host mounts a volume only when its signed desired state names the volume
OCID, device and mount point. It reuses the TerraBase data volume path
([runtime contract](terrabase-runtime-contract.md#data-volume)): it never
formats a device that has a filesystem, formats a blank one only with the
controller's one-time first-format grant, mounts `nosuid,nodev,noexec,noatime`
and grows the filesystem after a resize. A machine sees its volume as a bind
mount at its mount path.

## Migration

The gru-1 plan records no member data volumes, so the members' data is on
their boot disks. They move to managed volumes one member at a time, so
quorum is kept. For each member: create its volume (or adopt an existing
`<member>-data` volume), attach it and format it with a grant; copy the live
data directory to the volume; stop the member, copy the changes and switch
`<root>/data` to the volume; start it again and let TS-561 replication catch
it up. ts-auth needs no volume: its state is its TerraBase database
([ts-auth deployment](ts-auth-deployment.md)).

## Cost

OCI bills $0.0255 per GB-month of storage plus $0.0017 per VPU per GB-month,
so Balanced costs $0.0425 and Lower Cost $0.0255. Always Free covers 200 GB
of boot and block volumes together in the home region, and 5 volume backups.
Boot volumes use most of that: three 50 GB members already take 150 GB, so
their three 50 GB data volumes (300 GB in total) put the cell over the free
tier, and the first day of daily snapshots uses up the free backups.
`ts-orch volumes cost` will report boot and managed volume GB against the
free 200 GB and the monthly estimate. TerraBase members use Balanced; Lower
Cost is for volumes without latency-sensitive I/O, such as restore and fork
scratch volumes.

## Slices

1. Model, store, placement check and this note. **Done.**
2. OCI: managed volume create with KMS key, VPUs, backup policy, tagging,
   adoption and delete.
3. Leader reconciler: bind, create, attach, detach, grow, destroy, purge,
   with status write-back and decision journal records.
4. Host mount from signed desired state, and the machine bind mount.
5. Snapshot records, restore, fork for new replicas, and move across zones.
6. `ts-orch volumes` CLI and cost report.
7. Migration of the gru-1 TerraBase members.

Volume records use the app name, machine ID and region rules of
[`internal/machines`](../internal/machines) (TS-563). Its `MachineConfig` has
no mounts yet; slice 4 adds `mounts` there as `[]volume.Mount`, the Fly
shape.
