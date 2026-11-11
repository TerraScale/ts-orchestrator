# Cold maintenance operator tools

These tools implement the reviewed cold plan's individual gates. They do not
publish a deployment or provide remote access. Production execution requires the
parent's GO, all-six access/exit evidence, and exact green-main artifacts. Run each
host step separately and retain all six receipts before advancing a fleet barrier.
Do not run a fleet replacement loop that advances when a host is unreachable.

Use an existing private transaction directory (`$txn`, mode 0700); the following
variables are reviewed paths or identities, not literal commands to invent during
an outage. Every input containing authentication material is an owned 0600 file.
Credentials never belong in argv, environment dumps, receipts, or git.

## Prepare and close/open the maintenance gate

```sh
python3 scripts/maintenance/cold.py gate render --operator "$operator_ip" > "$txn/gate.nft"
sudo python3 scripts/maintenance/cold.py runtime-labels --receipt "$txn/runtime-labels.json"
sudo python3 scripts/maintenance/cold.py gate close --operator "$operator_ip"
sudo nft -j list table inet ts_zdt_20261105 > "$txn/gate-readback.json"
# Exact reversal, only after the data/auth/health barriers pass:
sudo python3 scripts/maintenance/cold.py gate open --operator "$operator_ip"
```

The independent inet table resets TCP packets to ports 80/443/5432/8081,
including established connections and IPv6. Only the exact operator IP and the six
NetBird peers' internal 8081 traffic pass its rules. SSH, NetBird and NATS retain
the existing firewall policy. An accept in this table does not bypass another
firewall's drop. Loopback auth/dashboard pools are closed too. Read back their
actual TerraBase upstreams: if an application uses an allowed peer-source path,
account for and stop that application's exact writer process first. Do not claim
network identity distinguishes replication from application traffic on that path.
Do not allow customer ingress from an operator NAT shared by customers.

Test negative public and loopback requests and positive operator/peer requests on
each host, then wait at most 20 seconds for admitted work to settle. A successful
nft command alone is not proof that every application writer is held. Abort before
stopping any engine if the gate, drain, runtime labels, or negative probes fail.
Runtime-labels examines every containerd namespace/container; missing/`no`/`never`
restart policies pass. Any other restart policy fails. Capture the original full
labels and prohibit any restart supervisor before stopping containerd. A service
`Restart=always` does not restart after an explicit `systemctl stop`; a socket or
external trigger does, and must be ruled out using the live dependency readback.

## Mandatory 60-second no-reappearance barriers

The installed `service rm` command is not a cold last-node stop: it still calls
regional handoff before TERM. Production remains held until the parent resolves
worker execution access. No helper here supplies remote access or bypasses that
approval. The following are implemented **local** commands, not invented node RPCs.

Capture a fresh root-owned task baseline before stopping anything:

```sh
sudo python3 scripts/maintenance/cold.py watch-baseline --receipt "$txn/watch-baseline.json"
```

After each physical stop and before advancing the fleet barrier, run on that node:

```sh
sudo python3 scripts/maintenance/cold.py watch --baseline "$txn/watch-baseline.json" --barrier stopped --runtime-down --receipt "$txn/stopped-watch.json"
```

After step 5 restarts containerd and ts-orch, repeat on all six with the runtime
API required readable (omit `--runtime-down`):

```sh
sudo python3 scripts/maintenance/cold.py watch --baseline "$txn/watch-baseline.json" --barrier restarted --receipt "$txn/restarted-watch.json"
```

The duration is fixed at 60 seconds; there is no shorter operator setting. Root
scans host `/proc` for native `/app/terrabase`/`tb-server` and managed TerraBase
entrypoints, checking start identities independently of the daemon. All containerd
namespaces and task identities are observed. Runtime-down mode requires an absent
or refused socket and checks the shim task directories independently; API failure
in restarted mode is an abort, never zero tasks. New/recreated task directories,
new task IDs, changed live PID/start identities, or live engine tasks abort.
Only already-inventoried non-engine task identities may remain running. Unreadable
proc/runtime state aborts. Inspecting an operator script argument that happens to
mention TerraBase does not classify that script as the engine.

Each invocation creates `abort:true` before observing, fsyncs progress and atomically
replaces the receipt; only a complete passing watch records `abort:false`. The
72-second outer deadline also leaves an abort receipt. SIGKILL or a missing,
truncated or invalid receipt is an abort. Transfer the six private receipts using
approved access into the transaction directory, then consume them as an explicit
input to the next barrier:

```sh
python3 scripts/maintenance/cold.py watch-check --barrier stopped --receipts "$txn/gru-1-stopped.json" "$txn/gru-2-stopped.json" "$txn/sjc-1-stopped.json" "$txn/sjc-2-stopped.json" "$txn/fra-1-stopped.json" "$txn/fra-2-stopped.json"
python3 scripts/maintenance/cold.py watch-check --barrier restarted --receipts "$txn/gru-1-restarted.json" "$txn/gru-2-restarted.json" "$txn/sjc-1-restarted.json" "$txn/sjc-2-restarted.json" "$txn/fra-1-restarted.json" "$txn/fra-2-restarted.json"
```

The checker rejects a wrong barrier, any abort, incomplete duration, duplicate or
missing host. A stopped-barrier receipt cannot authorize post-restart activation.
Repeat after any additional stop/restart; use the current transaction's receipts,
never a prior rehearsal's files. These observations certify only the watched
interval, so retain the runtime/executor barriers through the subsequent steps.

`qualify-watch.py`, Slow only on a dev host, uses private PID/mount
namespaces, real proc scans and task directories, plus runtime API contract
fixtures. It exercises both full 60-second barriers five times and checks abort
receipts for real process reappearance, task creation, unreadable API and bad fleet
receipts. This does not claim live worker qualification or install access.

## Physical exit, retained files, backup

After the all-six containerd-stop barrier, with socket availability checked,
use each captured JSON identity (`pid` integer, `start` proc start-tick string,
`exe` exact readlink result). The stop command rechecks identity and sends signals
through a pidfd, so PID reuse cannot redirect a signal:

```sh
sudo python3 scripts/maintenance/cold.py stop --identity "$txn/engine-identity.json" --receipt "$txn/exit.json"
sudo python3 scripts/maintenance/cold.py backup --roots "$txn/data-roots.json" --destination "$txn/cold-copy" --password "$existing_backup_passfile"
```

TERM has 20 seconds; KILL has 5; the command has an outer 28-second hard deadline.
A zombie has physically exited; an unknown/reused PID is a refusal, never success.
Independently scan processes/listeners and prove no replacement before moving on.
Keep all six exit receipts, not just health or runtime failures. No key mutation
until every engine/watcher is gone. No source deletion, checkpoint, vacuum, format
change, or old-data overwrite is performed by the backup command.

`data-roots.json` is the exact nonoverlapping array of absolute real data
roots, resolved from the retained service/task mounts, including catalogs, DBs,
WAL/journals and R10 hold directories. Unexpected symlinks/devices fail; resolve
actual mount roots in preparation rather than silently omitting them. The tool
keeps a full local data copy and records source/copy SHA256, mode, uid/gid, bytes,
AES-256-CBC/PBKDF2 archive SHA256, full decrypt/tar readback and measured duration.
The encrypted manifest hash authenticates the retained archive against accidental
or substituted bytes; keep that receipt separately. Use the already-approved
backup passfile. Do not create a new credential during this run.

Copy `data.tar.enc` and `manifest.json` using existing authorized dev-host/backup
transport, with an outer 60-second deadline. On the destination use
`sha256sum -- "$archive"` and `stat -c %s -- "$archive"`; require exact manifest
`encryptedSha256` and `encryptedBytes`, and retain transfer elapsed time. Use a
new destination, never overwrite an older backup. No bucket, credentials, SSH key,
or paid capacity is provisioned. **The local qualification's byte/time measurement
is not a production-size or off-host transport measurement.** Actual six-node
inventory sizes and equivalent-size rehearsals over each actual transfer path
must set each node's budget to ceil(measured duration × 1.5). Require the largest
parallel node budget to fit the plan's reserved 150 seconds before GO; otherwise extend the
announced window or revise the backup step with the parent.

## Logical row/schema hashes and applied positions

```sh
python3 scripts/maintenance/cold.py row-hash --address "$node_ip" --region "$region" --credential "$peer_file" --receipt "$txn/home-before.json"
# After collecting a home catalog from each region, include foreign-home replicas:
python3 scripts/maintenance/cold.py row-hash --address "$node_ip" --region "$region" --catalogs "$gru_catalog" "$sjc_catalog" "$fra_catalog" --credential "$peer_file" --receipt "$txn/all-before.json"
# Repeat at the post-start barrier, then:
python3 scripts/maintenance/cold.py compare --before "$txn/all-before.json" --after "$txn/all-after.json"
```

Use the actual internal authenticated sync/checksums contract with HTTP/2. Catalog
and range pages are bounded and fully paginated. Every DB's revision must stay
fixed throughout its hash; a moved revision fails. Schema ranges repeated on
pages are checked/deduplicated, not added to table row counts. Native hashes retain
rowids, nulls, blob bytes, value types and ordered schema. Keep revision/applied
position evidence; compare logical rows/ranges separately from revision incarnation
and cold byte checksums. Keep region-only platform catalogs scoped to their home.
Catalog union includes foreign-home replicas on each node; a region's home-only
catalog is insufficient as a complete replica inventory. Validate that the union
matches the cold mount inventory before calling it complete. Do not use public
SQL's 10,000-row response as an exact inventory.

## Exactly two conditional KV tombstones

The private approved audit maps the two `home.000…003` / `home.000…004` keys to
`revision` (last subject sequence) and `sha256` (exact raw value). Independently
require the previously audited SJC2/epoch3/no-TTL values and all placements local.
The tool deliberately has no arbitrary-key option.

```sh
python3 scripts/maintenance/cold.py kv dry-run --token "$nats_token_file" --audit "$txn/stale-key-audit.json" --receipt "$txn/kv-dry-run.jsonl"
# Only after all six physical exits, while old NATS is still available:
python3 scripts/maintenance/cold.py kv delete --token "$nats_token_file" --audit "$txn/stale-key-audit.json" --receipt "$txn/kv-delete.jsonl"
```

Both values/revisions are checked before the first mutation. Each empty DEL
publish uses `KV-Operation: DEL` and
`Nats-Expected-Last-Subject-Sequence`; a raced revision refuses that write.
Each successful quorum tombstone readback is fsynced to the private JSONL receipt
before attempting the next key. A partial receipt stays available after failure.
Never retry the same two-key audit blindly: reconcile receipts/tombstones first,
and have the parent review an audit for any remaining exact key. Never purge,
restore JetStream, delete owner/protocol/prepared records, or reinsert stale keys.

## Status notice, separate GO step

```sh
python3 scripts/maintenance/notice.py render --form "$txn/approved-notice.json"
# Parent publishes, or explicitly delegates with an existing admin cookie:
python3 scripts/maintenance/notice.py publish --form "$txn/approved-notice.json" --cookie "$existing_admin_cookie_file" --receipt "$txn/notice.json"
```

Form fields: title, message (impact/next update time), scheduledStart/scheduledEnd
(strict UTC), components (explicit existing IDs). This uses the real authenticated
admin form, its CSRF token, normal notification path, redirect receipt and public
readback. It does not edit measured component status. No session creation/login,
direct D1 write, announcement or notification is part of local qualification. If
publication times out, reconcile public history before retrying to avoid duplicate
subscriber notices. A local form/contract check is not a published notice.

## Workers: OCI stop receipt and offline boot-volume install (plan v4)

There is no worker shell. A STOPPED worker is the physical-exit proof:

```sh
cold.py oci-stopped --host ts-fra-2 --region eu-frankfurt-1 --instance-id "$worker" --receipt stopped-ts-fra-2.json
cold.py watch-check --barrier stopped --receipts <3 founder watch receipts> <3 oci-stopped receipts>
cold.py watch-check --barrier restarted --receipts <3 founder watch receipts>
```

On the founder, with a clone of the STOPPED worker's boot volume attached rw and
mounted at `/mnt/zdt-ts-fra-2`. First pass the founder reboot gate (README of plan
v4); a founder must never reboot while a clone is attached. The binary and
cold.py are staged in `/var/tmp/zdt-offline` (root, 0700; `/run` is noexec).

```sh
s=/var/tmp/zdt-offline
sudo $s/terrascale-orchestrator bootstrap-maintenance pins-offline --root /mnt/zdt-ts-fra-2 --state /var/lib/ts-orch
# must equal the prepared worker manifest's local.source (manager's last running task)
sudo python3 -I $s/cold.py offline-install --root /mnt/zdt-ts-fra-2 --manifest $s/manifest-ts-fra-2.json \
  --binary $s/terrascale-orchestrator --binary-sha256 "$green" --old-sha256 "$b443_orch" \
  --instance-id "$worker" --receipt $s/install-ts-fra-2.json
sudo python3 -I $s/cold.py offline-verify --root /mnt/zdt-ts-fra-2 --install-receipt $s/install-ts-fra-2.json --receipt $s/verify-ts-fra-2.json
sudo umount /mnt/zdt-ts-fra-2   # then OCI detach; re-check /dev/disk/by-label/* on sda
```

`offline-install` arms the fence offline (`arm-offline`), moves the old agent
`tasks.db` aside, installs the binary (old one kept as `.zdt-b443`), `cold.py`,
and the enabled oneshot `ts-orch-cold-drive.service`. Both receipts are required
before the clone is attached as the worker's boot volume. On first boot the unit
runs `cold.py boot-drive` once: IMDS instance check, 60 s rebooted watch, `stage`
(≤300 s), best-effort `prepull` (≤300 s), followers poll `owner` (≤900 s), then
`replace` and require `verified`. Receipts stay in `/var/lib/ts-orch/zdt-drive/`
on the volume; read them by stopping the worker and attaching its volume read-only.

The operator uses the same new executor actions on founders:
`bootstrap-maintenance owner --id <job>` (read-only: pinned owner is the ready
writer and released ingress) and `prepull --id <job>`.

Rehearsal on clones only: `python3 qualify-offline-worker.py TARGETS.json BINARY
OLD_SHA256 3 OUT.json` (clone, attach, install, verify, detach, delete; founders
checked clean). Boot-drive ordering: `python3 -I qualify-boot-drive.py`.

## Local qualification

`python3 scripts/maintenance/qualify.py` on a dev host, from a checkout of `<base>`
with the exact candidate overlay. Two critical integration cases cover the real
nft apply/undo in an isolated network namespace, actual TERM→KILL/physical exit,
full backup/encrypt/readback, real dev JetStream conditional DEL, repeated checksum
pages, and refusals for raced keys/unsafe labels/symlinks/changed revisions. No
production network namespace, process, KV, customer DB or status page is mutated.
