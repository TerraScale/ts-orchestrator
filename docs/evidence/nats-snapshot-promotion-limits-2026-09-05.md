# Clarifications to the frozen empirical report

The historical REPORT.md and its hashes remain unchanged.

- The GRU-outage phase reads all retained streams, KV/object contents and consumer checkpoints through SFO/FRA. It establishes read availability during that outage. It does not publish or acknowledge a new record with GRU stopped, and must not be described as a two-node commit or write-quorum proof. The exact-next-record publish and DoubleAck occur after all three brokers restart.
- The historical phrase "fenced original standalone store" refers only to stopping the original broker and verifying that its file-store digest remains unchanged. The experiment does not establish durable runtime-authority fencing, credential revocation, or protection against restarting another writer on that original directory.
- The revised permanent test now says "stopped original" and "read availability only". It additionally compares FirstSeq, LastSeq, NumDeleted, Msgs and Bytes through restore/promotion/restart, alongside full raw records and consumer checkpoints, to pin allocator and deleted-record state.

## Integrated restart failure

The first combined `make check` failed in
`TestInitialProfilesSnapshotRestoreR3Recovery` after the full cluster restart.
The last observation named `CELL_EVENTS/runtime_startup` with a changed consumer
creation identity or replica setting. The complete local log is
`/tmp/ts-receiver-promotion-check.log`.

A diagnostic repeat isolated a changed consumer `Created` timestamp while
replicas remained R3 and delivered/acknowledged sequence positions remained 1/1.
This contradicts any general claim that the original consumer creation timestamp
is stable through snapshot restore, promotion and restart. The historical
successful samples remain valid observations, but do not establish that invariant.
The permanent regression now qualifies content recovery and characterizes the
metadata defect explicitly. No production restoration identity qualification
follows from the earlier samples.

## Confirmed metadata persistence defect

On NATS v2.14.6, restore initially preserves original consumer `Created` in the
API and GRU metadata file. Promoting each consumer to R3 rewrites GRU's
`meta.inf` with its restore-time creation value. SFO and FRA retain the original
assignment timestamp. All three original consumers exhibit this divergence.
After a cluster restart, the public value depends on the consumer leader.

The server's `stream.go:9255` restores a consumer without a cluster assignment
and then calls `setCreatedTime`. `consumer.go:1202` initially uses the current
time, which `filestore.go:12882` captures in `FileConsumerInfo`. The restored
metadata file initially prevents an overwrite. `consumer.go:2071` changes only
the consumer's in-memory creation time. `filestore.go:13379` later writes the
cached file metadata during `UpdateConfig`, exposing the inconsistent time.
These references are for the pinned v2.14.6 source. No vendor code or retained
store metadata was modified. No released fix was found during this audit.

The permanent `PinnedNATSConsumerCreatedMetadataDivergence` subtest checks this
disk discrepancy before any restart. Subsequent API timestamps must match
values captured from that consumer's three stores. It does not accept arbitrary
new timestamps. Original creation timestamps remain strictly checked immediately
after restore and before the discrepancy is recorded. A vendor fix will fail
the known-defect assertion and require review.

Exact records, headers, message timestamps, sequence allocation, deleted-record
state, stream and consumer configuration, consumer checkpoints, R3 placement,
KV/object semantics, next-message delivery and the unchanged stopped source
directory remain required. Three consecutive focused race-enabled runs passed
in 55.511 seconds. This qualifies content recovery only.

Local evidence SHA-256:

- `/tmp/ts-profile-recovery-stage/disk.log`: `0ebb18bf52d2581fa92a2748ca4a2771b572932120e49f841e089e2c86ed5ed7`
- `/tmp/ts-profile-recovery-stage/result-race.log`: `4fe9d5f576f6e39b0616144180e14c1d4c922c1c7671d6ae7b471f99d593b251`
