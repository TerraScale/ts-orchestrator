# Disaster recovery

What TerraScale can actually recover today, what it cannot, and what each
failure costs. Facts checked 2026-11-13. Anything missing is marked **Gap:**.

## What is backed up today

**TerraBase data** — every customer database, `_system`, and ts-auth's data
(ts-auth stores everything in TerraBase) from all 3 regions / 6 nodes ships to
one Tigris bucket, `terrascale-gru-terrabase-backups-b12`, named by
`BUCKET_NAME` in [`deploy/m1/services/terrabase.json`](../deploy/m1/services/terrabase.json).
WAL segments ship every 1 s; a snapshot lands daily; the bucket keeps 7 days
(`TERRABASE_BACKUP_RETENTION_DAYS`). Tigris snapshots the bucket daily and
keeps those snapshots 14 days. Each node runs a daily snapshot restore drill
(no WAL replay): it rebuilds a file from the bucket and compares it with the
live file at the same frame position. Customer databases restore to any
second in that window; `_system` restores only to snapshot times, so up to
24 h of catalog changes can be lost.

**Boot volumes** — the policy `ts-boot-weekly-4` (Sunday 00:00 UTC,
incremental, 28 days retention, no cross-region copy) is assigned on all six
hosts since 2026-11-13, plus one manual backup per host
(`ts-boot-initial-20261113`). Check coverage with
`ts-orch region backups <code> --check`; see
[boot volume backup policies](boot-volume-backups.md).

**Secrets** — the TerraBase master key, the backup and files keys, the
terrabase peer secret and the NATS token exist only in the São Paulo OCI
Vault, delivered to hosts by instance principal.
**Gap:** no copy of the Vault exists elsewhere; losing it makes every backup
unreadable.

**Not backed up** — each one a **Gap:**:

- ts-orch state (`/var/lib/ts-orch`) and NetBird server state live on boot
  disks beyond what the weekly boot backup captures.
- Customer files in R2 (`terrascale-{gru,sjc,fra}-files`).
- A second-provider copy of the TerraBase backups.

JetStream is not backed up, by design: it is a transient work queue, not a
system of record. Desired state is in git (`deploy/m1`), which is its backup.

## Recovery targets

Targets, not measured; the drill below measures them.

| Failure | RPO (Target) | RTO (Target) | How |
| --- | --- | --- | --- |
| Node or disk lost | 0 when a peer has the data, else ≤60 s | ≤60 min | Rebuild host, peer resync or restore |
| Region lost | 0 for multi-region databases, ≤60 s single-region | capacity in 4 h | Remaining regions serve; rebuild region |
| Bad data written | any second in 7 days | 30 min per database | Point-in-time restore |
| Backup provider lost | Gap: no second copy | Gap | — |
| Master key lost | Gap: no escrow | Gap | — |

## Runbooks

### Node or disk lost

1. `ts-orch member ls` — see the region's hosts; `ts-orch member drain <hostname>`
   stops task placement on a sick worker before it fails.
2. `ts-orch status` — confirm the cell reports `ok` or `degraded`, not `down`.
3. Replace the host: `ts-orch node retire --node N` (drains, backs up the
   boot volume, terminates), then provision a replacement and enroll it.
4. If data was lost with the disk, TerraBase restores it: peers resync a
   replica; otherwise restore the member's data volume from backup
   (`ts-orch terrabase restore-volume`) or point-in-time restore the
   databases (below).
5. **Gap:** no single command rebuilds a host end to end yet; the steps are
   manual.

### Region lost

1. `ts-orch mesh` — confirm the surviving regions still answer on the
   cross-region mesh; multi-region databases keep serving.
2. `ts-orch status` — confirm degradation is limited to the lost region.
3. Rebuild: `ts-orch region plan <region>` derives the region's plan,
   `ts-orch region create BUNDLE` provisions the footprint,
   `ts-orch region verify LABEL --plan BOUND_PLAN` proves it serves.
4. Single-region databases in the lost region lose at most 60 s of writes
   (WAL shipping interval); restore them to any second with
   point-in-time restore (below).
5. **Gap:** region rebuild is not exercised end to end on a schedule; the
   4 h capacity target is untested.

### Bad data written

1. `ts-orch observe backups --database ID --partition ID` — read the backup
   state of the database (requires canonical ULIDs).
2. Point-in-time restore to any second within the 7-day window, 30 min per
   database. **Gap:** no `ts-orch` command drives a point-in-time restore
   yet; the API exists on TerraBase but only the owner can call it today.
3. Verify the restored data through the application before releasing it.

### Backup provider lost

**Gap:** the Tigris bucket is the only copy of the TerraBase backups. There
is no second provider and no command to create or sync one. If Tigris loses
the bucket, recovery ends at whatever the surviving nodes and R2 files hold.

### Master key lost

**Gap:** the master key exists only in the São Paulo OCI Vault with no
escrow. No command backs it up or rotates it; losing it makes every backup
unreadable. Recovery is limited to the Vault's own durability.

## Drill

The throwaway drill (provision a scratch cell, break it in a controlled way,
measure the targets above) is planned. **Gap:** not built; no command drives
it. Production drills need owner-approved dates: they take real capacity and
risk real data, so nobody schedules one autonomously. Evidence from a drill
or a real recovery goes to `docs/evidence/dr-<region>-<date>.md`.
