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

The independent inet table resets TCP packets to ports 80/443/5432/7464/8081,
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
inventory sizes and a timed existing-transport rehearsal must fit the plan's
150-second backup/readback/transfer budget before GO; otherwise extend the
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

## Local qualification

`ts-heavy-any python3 scripts/maintenance/qualify.py --repo ts-orchestrator --branch <base>`
with the exact candidate overlay. Two critical integration cases cover the real
nft apply/undo in an isolated network namespace, actual TERM→KILL/physical exit,
full backup/encrypt/readback, real dev JetStream conditional DEL, repeated checksum
pages, and refusals for raced keys/unsafe labels/symlinks/changed revisions. No
production network namespace, process, KV, customer DB or status page is mutated.
