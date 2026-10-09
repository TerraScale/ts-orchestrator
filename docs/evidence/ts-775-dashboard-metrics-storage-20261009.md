# TS-775: dashboard metrics and storage

## Live diagnosis and repair

Inspected the existing GRU and SFO cells from delta over NetBird on
2026-10-09. Dashboard reads used the regional Vault tokens without logging
them. No cell was rebuilt and no resource was re-provisioned.

The controller systemd unit combined `ProtectProc=invisible` with
`ProcSubset=pid`. Inspection inside the serving process's mount namespace
confirmed that `/proc/stat` and `/proc/meminfo` were absent. System collection
returned before filesystem sampling, losing CPU, memory and disk together.

Removed only `ProcSubset=pid` from the installed controller unit on each of
the six verified nodes. Reloaded systemd and restarted one controller at a
time, verifying readiness before proceeding. `ProtectProc=invisible` remains;
effective `ProcSubset=all` permits collection. Host agents remained active.

| Cell | Controller A | Controller B | Controller C |
| --- | --- | --- | --- |
| GRU | 10.200.87.215 | 10.200.38.135 | 10.200.168.164 |
| SFO | 10.200.112.213 | 10.200.122.37 | 10.200.63.195 |

Every controller changed from `ts_orch_collect_ok{section="system"} 0` to
`1`. After repair all six reported one CPU, approximately 4.09 GB RAM and
50,884,108,288 bytes for the measured filesystem. Controller A in each cell
reported 4,091,879,424 bytes RAM.

The following values are the final points extracted from the real HTML
`data-spec` chart payloads on `/members`, at 2026-10-09 20:47:00 UTC:

| Dashboard | Before | CPU after | Memory used after | Disk used after |
| --- | --- | --- | --- | --- |
| GRU | All three resource charts empty | 31.79% | 33.72% | 27.13% |
| SFO | All three resource charts empty | 35.39% | 29.81% | 10.71% |

Raw local captures are in `/tmp/ts775-live-before/{gru,sfo}` and
`/tmp/ts775-live-after-unit/{gru,sfo}`; successful scrapes of every controller
are in `/tmp/ts775-live-after-unit/all`. These are transient inspection files,
not committed secrets or a deployment artifact.

## End-to-end resource path

Host agents read system counters and actual configured filesystems, including
boot root, TerraBase data and native managed OCI member mounts. The authenticated load
report preserves filesystem role, path, device and capacity. The fullest-disk
ratio continues to drive autoscale; per-filesystem data serves presentation.

The authority leader validates reports and publishes bounded host samples to
the replicated `TS_HOST_METRIC_HISTORY` stream. Each controller replays that
history. Regional JSON, topology, hosts, host detail and Storage use the
granted physical node's authenticated host history. Controller-member charts
remain explicitly separate. Live configs disable controller aggregation;
node resources therefore do not depend on remote controller snapshots.

Absent measurements stay unavailable, observed zero stays zero, and old
readings carry freshness evidence. The archive retains the authenticated
controller receive timestamp: republishing an older report does not make its
measurements fresh. A newest report lacking a metric cannot borrow the prior
report's value. CPU and RAM capacities, inode counts and filesystem
bytes survive archive serialization and controller replay. Device identity
prevents multiple directory roles from counting one filesystem repeatedly.
Regional utilization totals include only fresh capacity/usage pairs from the
same report, flag partial coverage, and weight CPU utilization by core count.
Resource alarms also determine the topology node's overall status.
An unreadable or omitted configured filesystem sets a bounded incomplete
collection flag that survives host report serialization and archive replay;
successful filesystem readings cannot hide failed collection elsewhere.

Controller system collection additionally includes `/` and the NATS store;
the systemd regression test guards access to system `/proc` files.

## What Storage covers

1. **Disks:** measured host filesystems and controller JetStream usage.
2. **Retained volumes:** placement-owned volume and attachment evidence.
   A retained volume with cleared host/attachment IDs is unknown rather than
   healthy attached. Attach age uses the actual attach request timestamp.
3. **Object Storage:** configuration KV snapshots, separate from volume
   backup requests. Four objects already existed in each regional head
   bucket (`gru-1-head`, `sfo-1-head`, namespace `grxnmoqvrcdv`, prefixes
   `kv-snapshot/v1/gru/` and `kv-snapshot/v1/sfo/`). No recent uploader error
   was found. Existing writes were not proven broken; structured dashboard
   health was missing. The new snapshot view reports schedule, authority,
   checks, uploads, covered sequence and bounded failure classes, without
   document contents. Unchanged snapshots remain current after successful
   checks; overdue checks and a failed bucket cannot be hidden by another
   successful bucket. Each unchanged check reads Object Storage instead of
   treating an old cached upload as proof of current backend health. Refused
   reads remain failed; a missing unchanged object is uploaded again.

## Dashboard and API audit

All fourteen sidebar pages were fetched in both live regions. Findings below
include missing features separately from incorrect values; empty managed
placement is not proof that the static TerraBase services stopped running.

| Page / API | Live finding or source limitation | Disposition |
| --- | --- | --- |
| `/`, `/region` | CPU/RAM/disk absent; static services are not placement databases; cross-region summaries partial | Metrics in this PR. Managed placement counts must be labelled as such. GRU–SFO connectivity belongs to TS-774. |
| `/topology` | Services visible, physical-node resources absent | Node CPU, memory and filesystems in this PR. Existing names stay in TS-776 scope. |
| `/members`, host detail | Resource charts empty; hosts table covered placement seats only | Collection repaired live; all granted nodes gain readings and host detail from regional host history. |
| `/storage`, volume detail | Filesystems absent; no snapshot health; attachment state could claim unproven success | Metrics, snapshot health and attachment evidence in this PR. Placement inventory is distinct from OCI boot disks. |
| `/terrabase`, partition detail | Static TerraBase services run on topology while placement roster is empty; forecasts describe controller filesystems | Show service observations separately from managed placement. Scope forecasts explicitly. Replication/client history depends on TerraBase observations. |
| `/nats` | Local broker view only; route RTT is explicitly uncollected | Keep local scope explicit. Lag and truncated inventories must not imply complete health. Route RTT collection is follow-up TS-775 work. |
| `/oci` | API history excludes Object Storage; complete inventory provider is unattached; live OCI section reported no calls | Storage operation instrumentation in this PR; operation collection is independent of managed placement. TS-782 owns the empty OCI dashboard end to end. Its investigation should check nil `Inventory` in `attachJournal`, previously conditional `CollectorConfig.OCI`, absent Object Storage recording, and the distinction between placement fleet sweeps and static-cell inventory. Provider failures stay unknown. |
| `/ci` | Qualification provider unattached; admitted releases are separate evidence | Full qualification inventory is follow-up TS-775 work. Provider failures must remain unknown. |
| `/decisions`, decision detail | Cross-region search can be partial and says so | Preserve completeness warnings; regional API mounting fixed in this PR. |
| `/insights` | Rules without system input stayed silent | Collection repaired; preserve unknown-input reporting. |
| `/releases`, `/rollouts`, rollout detail | Remote history partial; optional providers incomplete | Preserve scope/completeness warnings. Complete version/qualification inventories are follow-up TS-775 work. |
| `/events` | Serving controller's event ring | Correct local scope; no fleet-wide claim. |
| NetBird `/v1/snapshot`, journal/history/regions/insights/summary APIs | 404 despite the same providers powering HTML | Mount available authenticated runtime providers in this PR. `/v1/cluster` remains absent when aggregation is disabled. |
| `/metrics`, `/v1/usage`, `/healthz`, `/readyz` | Served; system collection failed before repair | Successful six-node system scrapes after repair; authenticated resource/API regression coverage. |

Additional source findings: terminal placement records inflated active seat,
host, partition and rollout aggregates; failed filesystem reads emitted zero
gauges; volume backup decisions record accepted creates but have no later
completion observation. Active aggregates and missing filesystem gauges are
fixed here. Backup completion observation is follow-up TS-775 work; the
dashboard must describe those journal entries as requests, not available
backups.

## Deployment evidence boundary

Final local validation passed with `umask 022`:

```sh
nice -n 19 mise exec shellcheck@0.11.0 -- make verify build shellcheck fixturetest-check
```

This includes all Go race suites, the vendored NATS identity regression,
formatting, template generation consistency, vet, shellcheck, fixture tests
and the native binary build. An independent T3 pre-push review approved the
final diff after regression tests verified coherent capacity coverage,
topology resource alarms and failed filesystem collection/recovery.

The unit repair and restored controller charts above are already live. The
new binary's node tables, filesystem archive fields, snapshot health and API
mounts still require the signed release flow after COS merges. No unsigned
binary was substituted into a serving cell. Post-merge verification must
check every GRU/SFO node, the regional APIs, all pages and snapshot checks
under the current authority leader. TS-775 is not fully accepted until that
deployment and the separately tracked dashboard provider work are complete.

All API, report and archive schemas remain v1, edited in place. Host archive
batches now require an explicit format version of 1; unversioned records are
rejected. Deploying the changed host filesystem archive contract requires
deletion and recreation of `TS_HOST_METRIC_HISTORY` in each serving cell,
followed by fresh host reports;
there is no migration or backfill of old data. A retained unversioned latest
batch blocks publication, so the reset is a release requirement, not optional
cleanup. Existing host telemetry history is intentionally discarded.
Each recreated archive uses a fresh random generation subject under
`ts.orch.v1.<cell>.obs.host-metrics.<generation>`. Creation reads an existing
valid contract without changing it; an old unsuffixed subject or incompatible
archive configuration requires deletion. Publication and replay remain pinned
to one generation, including in-flight writes and identical-batch confirmation.

Perform these steps separately in GRU and SFO with the signed rollout:

1. Verify the regional NATS endpoint, cell identity, stream name and healthy
   three-controller quorum against the node addresses above. Record the
   stream configuration and message count without exporting payloads.
2. Roll the signed binary in place across all three controllers, preserving
   quorum and checking readiness after each restart. Verify every controller
   runs the new revision before deleting history; an old archive writer must
   not recreate unversioned records.
3. Delete only `TS_HOST_METRIC_HISTORY` using authenticated regional
   JetStream credentials authorized for this regional archive (ordinary
   read-only dashboard/operator credentials cannot delete it). Restart
   controllers one at a time, verifying readiness
   between restarts. Startup recreates the stream with the configured replica
   count; fresh process state also clears each replay cursor and in-memory
   history. Let controller startup create the new generation; do not restore
   the saved old stream configuration or reuse its generation subject. Old
   publication routes cannot enter the recreated stream. A bounded monitor
   checks reader identity every second independently of blocked SDK consumer
   retries, and replay validates identity before appending data.
   Restart provides fresh handles and state. Do not delete KV buckets,
   configuration snapshots or other streams.
4. Wait for the next regional minute of publication. Verify increasing stream
   sequence numbers, batches carrying `version: 1`, and all controllers
   reporting `ts_orch_host_history_replay_ready 1` and
   `ts_orch_host_history_archive_incomplete 0`. Verify fresh CPU/memory/filesystem
   evidence for every node in the API and dashboard. Do not accept the region
   until all checks pass.

`TestHostMetricStreamRecreationResumesV1Publication` exercises the actual
JetStream deletion/recreation boundary: an unversioned latest record blocks
publication, deletion removes it, and the recreated stream accepts and replays
a fresh v1 batch. No live archive reset has been performed before deployment.
`TestHostMetricPublicationRequiresRestartAfterArchiveRecreation` also exercises
the application's existing publisher through unversioned rejection across a
minute boundary and reset. Its old handle cannot insert the retained gap into
the new stream; fresh publication state after restart produces complete v1
history and healthy replay/coverage metrics.
Generation regressions exercise recreation immediately before publication at
reused sequence numbers, identical-body confirmation during message retrieval,
idle/caught-up reader reset with and without new data, and concurrent creation
converging on one subject. Opening an old contract never rewrites it.
Reader regressions hold the archive absent before recreation, ensuring SDK
retries cannot leave replay readiness true while the stream is deleted.

The PR #358 review corrections also have regressions for rendered snapshot
check timestamps, explicit overdue status with failed/stale precedence, and
64/65-node regional API coverage. Existing HTML/global KPI tests verify that
partial capacity carries a visible warning.

The next review identified bucket starvation within the bounded snapshot pass
and a management request for every replayed archive record. Snapshot passes
retain the two-minute limit and rotate their starting bucket under the existing
pass mutex. A persistently slow bucket cannot always precede healthy buckets;
each configured bucket gets first priority within eight active passes.
`TestSnapshotDeadlineDoesNotStarveLaterBuckets` failed before rotation and
now verifies next-pass uploads, wraparound, unchanged-object confirmation and
preservation of earlier successful evidence.

Archive replay buffers at most 64 compressed records and validates the pinned
generation before appending each chunk. It also flushes a short final chunk at
the captured replay target or iterator timeout, and advances its resume cursor
only for processed records. Per-message subject validation and the independent
identity monitor remain in place. Replaying 131 retained batches required
132 management requests before this change and four afterward.
`TestHostMetricStreamReplayBoundsManagementRequests` guards that cost;
`TestHostMetricStreamReplayDiscardsBufferedChunkAcrossRecreation` verifies
reset rejection leaves the buffered history, resume cursor and readiness
unchanged. `TestHostMetricStreamReplayResumesAfterInterruptedChunk` injects a
failed generation check and verifies recovery loses or duplicates no records.
Existing reset, malformed-record, reconnect, idle and concurrency regressions
still pass. No serving archive was reset for these local checks.

The next attachment review found a valid current-state path: placement can
observe an existing `ATTACHING` attachment and enter `awaiting-attach` without
issuing its own request. `AttachRequestedAt` is then absent, while `UpdatedAt`
records that phase's start and remains unchanged during the wait. The volume
provider now carries this observed phase-entry evidence into `StateSince`,
using the real request time whenever it exists. Prepared attachment work
without a request still has no attach age. The adapter-to-rule regression
`TestVolumeAttachmentTimingReachesTheStuckRule` failed before the fix with
zero stuck-volume warnings for an hour-old observed attachment; it covers
observed/requested timing, a recent attachment, unrequested prepared work
and unknown timing. This changes only the read model, not the stored v1
placement contract or data.

TS-794 owns cross-region NATS fan-out and global dashboard views. This PR
supplies regional metric and storage evidence; no new cross-region view is
included.

Rebased on TS-776's merge `6895b1f6` and TS-782's dashboard probe merge
`39ac4637` before the review-fix push. Rebase again if TS-774 lands first.
