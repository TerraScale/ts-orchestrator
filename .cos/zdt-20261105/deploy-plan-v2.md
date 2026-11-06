# Coordinated cold maintenance — v2, HOLD for review and GO

DECISION: Replace the six-node fleet during one announced stop-the-world window.
Reason: all b443 watchers can be physically absent before deleting the stale keys
or restarting embedded NATS. A hot mixed-version installation is unnecessary.

This supersedes deploy-plan.md. It is a plan, not an execution receipt. No announce,
production stop, key mutation, installation, workflow enable or rollout has occurred.
Independent review of the Version:0 guard, cold arming and this plan precedes GO.

Target: about 10–15 minutes from closing customer ingress to restored service,
including the status monitor's five consecutive passing minutes. Preparation and
artifact production happen before that clock. If the estimate stops fitting,
start the rollback while its original processes/data are still available; do not
wait indefinitely for CI, backup transfer, readiness or a missing node.

## Prepare before the announced window

- Freeze production publications for both repos; retain the current disabled
  CI/Images state until GO. After GO, use ts-ship and exact green-main artifacts,
  separating artifact preparation from application publication. No release intent
  may reach an unfenced executor. Verify that separation before beginning; do not
  invent a workflow input or count a canceled deployment as green qualification.
- Prestage the exact green arm64 engine image, new ts-orch executable and signed
  provenance on all six hosts. Retain the live b443 image/executable, old ts-orch
  executable, runtime specs/material references and hashes locally. No image pull,
  source build or new paid capacity belongs on the outage's critical path.
- Capture the three regional owner records/revisions, preparation/protocol records,
  six node statuses, all tasks/container IDs, immutable images, Swarm node/service/
  task/fingerprint pins, host PIDs and /proc start ticks. Expected, not prescribed:
  SJC1 epoch5, FRA2 epoch7, GRU1 epoch9. Require Version:0, no pending transfer and
  the same live owner throughout preparation. No manual owner/home CAS is planned.
- Audit all 12 platform placements and the two exact stale keys read-only. A
  foreign platform placement, changed owner or unexpected key value is a stop and
  report condition. Save the keys' complete encrypted/private backup, exact last
  subject revisions and stream configuration. Never print credentials or sessions.
- Capture controller/mesh desired state, deployment floors, retained release
  provenance, Swarm admission/Raft/agent state and root-owned configuration for
  an offline rollback. Do not copy a changing Raft database and call it a complete
  snapshot: its final retained copy is made after those daemons stop in step 5.
- Inventory every data mount and DB on every host, including catalogs,
  auth/dashboard builtins, replica files, WAL/journals and R10 hold directories.
  Measure total bytes and the backup transfer estimate. Reserve existing approved
  backup storage; no new bucket, key, credentials or capacity is required.
- Prepare six root-only cold manifests: each contains `local` and `owner` Job
  records with the captured pins/PID/start ticks. Both are initial `phase:"held"`,
  have no deadline, and name the same owner, epoch and target image. Target task
  and fingerprint are empty: the normal dispatcher supplies them later. The
  owner's record is included on its founder too, even when FRA's owner is -2.
  Retain one signed-off manifest hash and a six-node exit matrix with the evidence.
- Prepare a separate maintenance gate for public Data API, internal application
  writers, PostgreSQL/wire and auth/dashboard traffic. It must remain in force
  when the bootstrap driver releases its own regional hold. Allow only the
  maintenance operator's probes and engine/NATS peer traffic. Save and read back
  the narrowly scoped host routing/firewall changes and their exact reversal;
  do not replace the existing firewall or remove SSH/NetBird/NATS access.
- Read back the live systemd dependency graph before GO: stopping containerd
  must leave old ts-orch/embedded NATS running through step 4. The M1 unit has
  `Wants=containerd.service`; managed-host units with `Requires=` need separate
  verification and cannot be assumed equivalent. If the actual graph propagates
  that stop into NATS, revise this ordering before the window rather than testing
  it during maintenance. Retain the unit/dependency evidence with the restore set.
- Verify the local containerd service cannot be automatically/socket activated
  during the stop interval. Its restart policy and the task restart labels must
  be captured. Stopping containerd's control daemon leaves existing shim-owned
  processes alive; it is an executor barrier, not proof of TerraBase exit.

## Sequence, bounds and rollback

Times below are a budget, not observed production measurements. Only one operator
advances the numbered barriers, recording UTC start/end and source/target hashes.
All six hosts participate in the same transaction. CI and Images do not drive it.

### 1. Announce maintenance and close ingress (0–1 minute)

Publish the approved status-page maintenance notice with a 10–15 minute estimate,
impact on reads/writes/token issuance, and the next update time. Apply and verify
its independent maintenance gate. Let existing admitted requests/native writes
finish, then record the final acknowledged cutoff. With application writers held,
collect canonical per-table counts, schema and ordered row hashes plus latest
applied positions for every DB on both nodes. These form the logical baseline.
The hashing format must preserve nulls, blobs, types and deterministic ordering.

Abort: if the notice, gate, drain or inventory cannot be verified, do not stop any
process or change any key. Rollback: remove only this transaction's gate, verify
original b443 serving/token issuance and amend/cancel the notice. No data restore.

### 2. Stop TerraBase on all six, with no automatic recreation (1–2.5 minutes)

Keep old ts-orch/NATS running for the moment, but stop the containerd control
service on **all six** hosts first. Verify every runtime API is unavailable and
cannot restart automatically. This prevents the old executor from creating new
TerraBase tasks while the existing embedded NATS quorum remains available for
step 4. Do not restart ts-orch or NATS yet.

Signal TERM to each captured TerraBase host PID only after rechecking its start
ticks and executable identity. Do not call the legacy /drain endpoint. Wait for
physical exit and listener closure on all six; record PID/start identity, UTC exit,
container/shim state and absence of replacement PIDs. A failed API request, failed
health check, expired lease or dead parent is not exit proof. Preserve stopped
containers, data mounts and task-secret material. No new engine starts here.

Abort: if any old process remains or a runtime API returns, stop advancing and
retain the gate; do not delete keys, restart NATS or launch a second process.
Rollback: return to the captured b443 deployment only after every conflicting
process is physically accounted for. Complete the six-node stop and the two-key
cleanup in step 4 before restarting old watchers. This prevents an abort itself
from replaying the original stale-key hazard. If the complete stop cannot be
established, report the stuck host immediately and extend maintenance; do not
claim that a safe restart is available while process identity is unknown.

### 3. Checksum and back up every retained DB (2.5–5 minutes)

With every engine absent and no writer able to restart, record SHA256, path, size,
mode/ownership and DB identity for every retained data/replica/WAL/catalog/hold
file. Copy the complete cold data trees, including sidecars and R10 holds. Keep
an untouched local copy and an encrypted off-host copy on existing approved backup
storage; verify copy readback against the file manifest and record restore paths.
A peer replica alone is not this backup. Also preserve the logical cutoff baseline
and all applied positions. Do not open the source files with an incompatible SQL
client, checkpoint them, vacuum them, delete WALs or merge divergent copies.

Raw file hashes validate the cold backup and any restore. Post-start data equality
uses canonical logical row/schema hashes: normal native recovery may change byte
layout, headers, WAL shape and revision incarnations. A changed byte hash is not
silently accepted as proof of unchanged rows.

Abort: incomplete inventory, unreadable data, mismatched copy checksum or an
unbounded backup time prevents installation. Rollback: leave originals in place,
finish the safe two-key cleanup while all engines remain absent, then start b443
on those retained originals. Never delete a good source to finish a failed copy.
If the originals themselves are damaged, retain them and report recovery; do not
advertise an unverified restore or silently reset customer data.

### 4. Delete only the two stale platform keys (5–5.5 minutes)

All six engines/watchers must still be absent and containerd must remain stopped.
Use the existing, still-running embedded NATS quorum and a privileged local
session that reads its existing token from its protected file. Re-read:

- `home.00000000000000000000000003`
- `home.00000000000000000000000004`

Require the audited SJC2 epoch3 records and exact expected revisions. Write a KV
DEL tombstone conditional on each key's current last-subject revision; do not purge
the stream or edit JetStream files. Read back the tombstones from the quorum.
Record both outcomes individually. Do not touch any real customer home, node,
owner, writer, preparation or protocol key. Already deleted is accepted only with
this transaction's matching retained tombstone receipt.

Abort: changed key/revision, quorum failure or unexpected placement stops further
changes. Rollback: no stale-key reinsertion. Before any b443 watcher restarts,
confirm both hazardous records are deleted; retry only these conditional deletions
once quorum is available. Then b443 may use retained data and unchanged owners.
Deleting the second key after the first succeeded is completion of the same
reviewed cleanup, not permission to clear any other KV state.

### 5. Arm cold fences, install ts-orch, restart its control plane (5.5–7 minutes)

Run the **staged new executable**, not the still-installed old one, on each host:

```sh
"$new_ts_orch" bootstrap-maintenance arm-stopped --state /var/lib/ts-orch --manifest "$cold_manifest"
```

This implemented offline action requires root and the manifest's local hostname,
checks that the captured PID identity is gone and the fixed containerd socket is
unavailable, then uses the existing atomic/fsynced Store.Arm and HoldIngress APIs.
It initializes the local executor fence and the region's owner's ingress hold.
The full six-node exit matrix remains an operator prerequisite: a local check
cannot certify a remote host. A failed partial arm leaves a fence, never an
execution grant. Reconnect can repeat only the exact initial manifest.

Read back and retain every journal. Only then stop old ts-orch normally with
systemd on all six, take the final cold controller-state backup, and atomically
install the exact green qualified new binary with captured owner/mode and hash
readback. Keep the unit stopped while installing; no SIGSTOP, binary injection,
new host, new identity or rewritten database is involved.

Restart containerd, then new ts-orch. NATS/Swarm resume their retained state; every
TerraBase executor remains held before it can recreate b443. Confirm new revision,
control-plane membership, all six persisted fences, all three durable regional
holds and zero running TerraBase processes. A reappearing old process is an abort.

Abort: a missing fence, binary/provenance mismatch, unexpected task or NATS/store
failure retains maintenance and prevents engine start. Rollback: stop all new
orchestrators and account for every engine process, restore the captured old
orchestrator binary/control state and its b443 desired deployment offline, retaining
unchanged owner records and the two deletion tombstones. Bring back b443 on the
retained data only through the fleet rollback below. Do not restore hazardous
platform records from an earlier JetStream copy.

### 6. Start the new engine at the same owners and epochs (7–9 minutes)

Retain the existing authenticated release for the exact armed image. Stage it
through the normal applier using the two regional executor attestations:

```sh
ts-orch bootstrap-maintenance stage --state /var/lib/ts-orch --id "$local_job_id"
```

The initial owner ingress journals are already held. Consequently, the cold owner
path does not require a live old owner or call legacy /drain. Drive one retained
owner at a time (SJC, FRA, GRU), then its follower, using the implemented command:

```sh
ts-orch bootstrap-maintenance replace --state /var/lib/ts-orch --id "$local_job_id"
```

Each source is already physically stopped. Normal Swarm STOP_FIRST dispatch
provides its replacement task with the qualified image and original mounts,
identity and material. The driver rechecks old-process exit before Start. It never
invents a task spec or extends a lost deadline. Owners adopt Version:0 in place;
owner node and epoch must exactly match the pre-maintenance record. Only protocol
version/activation, session and exclusive writer admission may change. Followers
must remain Writer=false. Preserve their replication and R10 acknowledgement holds.

After the owner is up, replace its follower and prime it to the owner's applied
positions. The independent fleet maintenance gate stays closed even when a
successful driver releases its regional mutex/ingress journal. Require all six
on the exact engine revision, one exclusive writer/session per region, no pending
transfer, both copies caught up and all 12 platform placements still local.
Do not perform owner CAS, handback, promotion, format bump or data reset.

Abort: any owner/epoch change, failed activation, failed catch-up or expired 60 s
local driver budget stops the sequence. The budget retains the fence; no manual
journal deadline edit. Rollback: stop all new engines and controllers, prove all
six processes gone, let exclusive writer TTLs expire, then start the captured
b443 deployment on retained data as described below. Never let b443 and v2 writers
coexist, even though both name the same regional owner.

### 7. Reconcile data, canaries, token issuance and public status (9–15 minutes)

Before allowing application writers, compare every DB's schema, table counts and
canonical row hashes with the cutoff baseline. Check all retained acknowledged
inventories, both copies and R10 holds; record new applied positions and account
for incarnation changes. No unexplained missing, extra or changed user row is a
pass. Compare the cold backup's file hashes separately; do not expect recovered
live files' byte hashes to equal their cold originals.

Allow controlled application probes while customer ingress remains gated. With
one owned throwaway account, issue a token, write a unique canary through each
region and read each through GRU, SJC and FRA. Preserve exact IDs/responses and
all nine reconciled reads. Verify authentication, all regional/global health and
that each region still names its original owner/epoch. Delete owned probes after
recording the inventory. Do not alter the acceptance thread's retained account.

After all checks pass, remove only this maintenance transaction's customer gate,
recheck real token issuance and Data API routing, and allow five consecutive
minutes of passing public health. Verify the status page becomes operational;
monitoring incidents resolve automatically and need no fabricated manual fix.
Record the maintenance end and full source/target timeline. Retain executor
journals, backups and deployment freeze until the separately approved automation
reconciliation. This maintenance is not one of the three zero-downtime rollouts.

Abort: failed data comparison, canary, auth or health retains/reinstates maintenance
and begins fleet rollback. Rollback before organic writes reopen may use the
verified cutoff data copies, retaining failed candidate trees for analysis. After
organic writes resume, rollback must use the latest retained data containing all
new acknowledged customer writes; never restore an older snapshot over it.

## Fleet rollback: b443 on retained data

This is an explicit maintenance rollback, not a normal rolling deployment.

1. Close the independent maintenance gate. Stop runtime recreation, all candidate
   engines and new controllers. Prove every candidate PID/start identity gone on
   every host; preserve both failed and original data trees and R10 holds. Wait
   for the six-second exclusive writer lease TTL to expire and verify no v2 holder.
2. Keep the two stale platform keys deleted. Preserve current owner node and epoch;
   b443 ignores the new owner fields and writer-lease protocol. Do not restore an
   old JetStream snapshot over current real customer leases or reinsert the stale
   keys. An unexpected owner/epoch change needs incident handling, not CAS-back.
3. Restore the captured old orchestrator binary and the cold controller/mesh/Swarm
   state for the explicitly retained signed b443 deployment while all controllers
   are off. Preserve admission identities, release provenance and rollback receipts;
   do not forge a newer release, run an unsigned image or start a second executor.
   Prevent a queued candidate intent from being replayed by the restored controller.
   The restore set is recorded and reviewed before GO, not guessed during outage.
4. Start the old orchestrator/runtime and its b443 processes on each node's retained
   files, with original mounts/material and the same owner/epoch. No new process
   starts until its conflicting predecessor's physical exit is proved. Verify one
   serving owner per region; replicas and all acknowledged data remain present.
5. Compare the appropriate data baseline/current acknowledged inventory, issue a
   token, run all regional canaries, reopen ingress and verify public health/status.
   Leave failed artifacts and both workflow publications held; report the exact
   abort phase, data checks and measured recovery time.

Alpha reset authorization is available if recovery genuinely needs it; this plan
uses retained data and does not prescribe deleting customer DBs or re-founding
regions. There is no new capacity/credential request and no implicit permission
to restart a watcher before the all-six exit/key-cleanup barriers.

## Qualification and review inputs

- TerraBase rebased cleanly from 5fd89c3e7 onto a811367bd82e0cbe510cd2340fc93e25f81c2dd0;
  the five patch contents are unchanged by range-diff. Current candidate/manifest
  and affected Fast results are in qualification/v2-fast.md and its JSON.
- Orchestrator origin/main is still 2142b1f308b1c1169d25093f93eab3b10c479e1c;
  rebase was a no-op. Cold offline arming is an additional reviewed driver hunk.
- Prior engine Slow proof: 11 drills ×5, actual b443, target failures, blocked
  Version:0 certificate, same-region claim refusal and source-native row inspection.
  New Fast runs qualify the rebased source; no new live rollout proof is claimed.
- Independent review checks the Version:0 guard plus this whole-fleet ordering,
  offline arming, retained-state rollback and application/ingress gate reversal.
  Review and final GO are still pending. No production action is authorized now.

## v2 review closure addendum (2026-11-06; supersedes loose timing above)

HOLD: these are locally qualified candidates, not pushed releases or an approved
production run. All five review items are explicit gates. An unread worker, absent
backup transport, red main or lack of approved six-node control path prevents GO.
No production workflow was enabled and no serving process/key was changed by this
qualification. Only bounded read-only OCI commands were submitted, then canceled.

### A/C. Crash cuts, bounds, retained protocol keys

DECISION: Publish the activated owner CAS before the protocol marker; on restart
reassert a missing marker, and recognize the exact retained self-certificate for
Version:0/Previous:null. Reason: both old marker-first and new owner-first crash
cuts must be recoverable without handing a legacy owner's files to its follower.

The automatic recovery bound is 30 seconds **after the retained owner process has
restarted healthy with working NATS quorum** (includes the prior six-second
exclusive lease). No software can bound recovery while that pinned legacy process
is absent. Version:0 never grants a follower takeover; the maintenance executor
must restart its pinned owner or abort into retained-file rollback. Once an owner
is v2, either healthy regional node can recover a failed target via lease expiry
and persisted phases within the separately proven 30-second regional bound.

Keep owner node/epoch/value bytes, protocol and prepared keys on b443 rollback.
Keep protocol/prepared revisions unchanged too. The old process may renew the
identical owner value with a fresh CAS revision; do not mistake that for ownership
change. Never rewind owner metadata, delete valid certificates or restore an older
JetStream snapshot. The real-b443 rollback drill uses the same files and retained
keys, acknowledges a row in v2, another in b443 and another after re-upgrade, and
reconciles every acknowledged ID/value. This replaces any implicit key-reset rule.
Both crash cuts and the real-b443 retained-file rollback are in the full Slow ×5
qualification; exact observations belong in qualification/v3-results.md.

### B. Exact controller/Swarm rollback restore set

Before preparing candidate desired state, retain the original signed b443
`mesh/desired.json` **on all six nodes**, every `mesh/bake-terrabase-*.json`,
their generation/deployment/floor/provenance hashes, original service/task specs,
node availability, immutable image and material/mount references. Require every
peer's selected TerraBase entry/floor to name the same retained b443 deployment;
an unapplied newer candidate is a preparation failure, not something to silently
edit out. Stop publication before taking this snapshot and retain that hold through
rollback. Mesh anti-entropy reimports peer candidates every 30 seconds, so restoring
just one founder cannot suppress a queued candidate.

After all engines are gone and all six old ts-orch daemons are stopped, capture
these exact trees/files with owner/mode/hash manifest, using each actual inventory:

- `/var/lib/ts-orch/swarm/`: entire certificates, admission, agent/worker state,
  manager Raft/snapshots and metadata; omit only dead runtime sockets/locks from
  the archive, never logical records. Snapshot every member while the entire
  regional cluster is offline, not a live partial Raft copy.
- `/var/lib/ts-orch/mesh/desired.json` and `bake-terrabase-*.json`: original b443
  desired candidates/floors and verdict/provenance records captured **before**
  staging; keep non-TerraBase services as captured. Retain `mesh/client.token`
  privately. Do not treat the whole mesh directory as replaceable: embedded
  JetStream lives under it and must be retained at its latest state.
- `/var/lib/ts-orch/nats/`: retained original release-run-id, release-trial,
  release-rolled-back and TLS material, only as required for that exact original
  binary/probation. Inventory each existing file; absent files stay absent. Keep
  these receipts private. Do not manufacture a newer run ID or signing identity.
- Original `/usr/local/bin/terrascale-orchestrator`, its symlink and any `.prev`
  inode, actual `/etc/systemd/system/ts-orch.service` and drop-ins, containerd unit
  and drop-ins, six runtime task specs, authenticated material references, and
  the locally retained b443 image/content-addressed blobs. Keep all mount/data and
  R10 hold paths at their current retained versions.
- Keep the cold executor/ingress journals and all subsequent receipts in the
  transaction archive. A b443 controller does not implement these new fences:
  they cannot be its protection. Keep the independent customer gate closed,
  old/new engine physical-exit barrier complete, all publishers held and restore
  the original b443 Swarm deployment across all nodes before starting old daemons.

Restore the whole original Swarm cluster offline as a consistent set, and restore
the original desired/bake state on every mesh peer before starting any old daemon.
Move the failed controller trees aside for evidence; never overlay a running Raft
directory. Retain current JetStream account stores, real home/owner/writer leases,
protocol/prepared keys, and both stale-key DEL tombstones. Never restore these from
the controller backup. Plain mesh Apply publishes are not a durable intent queue;
peer `desired.json` candidates/floors and Swarm desired specs are the replay sources.
A publisher still able to send a new intent defeats rollback and is an abort gate.
If exact original selected state cannot be established, do not start b443 against
candidate desired state; retain maintenance and report the missing restore artifact.

### D/E. Executable gates and hard aborts

The committed source is `scripts/maintenance/{cold.py,notice.py,qualify.py}` and
`README.md`; that README contains the real invocation for each reviewed gate,
reversal, backup readback/transport verification, row/schema hash inventory,
conditional DEL dry run, and authenticated status notice. No helper is an invented
remote-exec command. Parameters identify inventoried inputs and existing authorized
access. If the worker command path is unavailable, the driver cannot execute there;
source derivation does not grant remote execution.

Each numbered barrier requires all six receipts. Record a single UTC gate-close
`t0` and monotonic elapsed times. Commands have their own hard deadlines; reaching
a fleet deadline invokes the abort/rollback for that step, never extends it.
No target starts while any predecessor's exit is unknown.

| Barrier complete | Hard elapsed limit from t0 | Failure action |
| --- | ---: | --- |
| Notice public, gate + negative/positive probes, drained logical cutoff | 75 s | Undo only owned nft table; verify retained b443 and amend notice. No process/key change. |
| Runtime APIs down, six exact engine PIDs physically gone | 120 s | Stop advancing; no NATS restart/key change/new process. Account for stuck host. |
| Cold local + encrypted off-host backup readback | 270 s | Leave originals untouched; complete safe two-key cleanup before b443 watcher restart. |
| Both exact conditional tombstones read back | 290 s | Reconcile each private receipt; no blind retry/reinsertion; keep engines absent until both hazards are gone. |
| Six fences, offline controller snapshot, new ts-orch/NATS up, no engine | 380 s | Keep gate; fleet retained-state rollback, excluding JetStream. |
| Six exact new engines at original owner/epoch, replicas caught up | 530 s | Fleet rollback after physical exit and six-second exclusive TTL. Each local replace also retains its independent 60 s bound. |
| Logical reconciliation, token issuance, all nine canary reads; reopen | 600 s | Reclose/retain gate and rollback against latest retained acknowledged data. |
| Five minutes passing checks and operational status | 900 s | Report measured incident; never override measured component status. |

The 150-second cold-backup budget includes readback and off-host transfer, not just
copy initiation. Preparation must measure actual source bytes and the authorized
transport's elapsed time before GO. A small dev fixture is not evidence that the
production inventory fits. If it does not fit, the parent revises the announced
window before closing the gate. If physical exit is unprovable or quorum is down,
a hard abort does not magically make rollback safe: retain maintenance and report
at once rather than launch a conflicting old writer to meet the clock.

The exact stop tool pins a PID/start/executable and uses a pidfd; TERM20s → KILL5s,
outer28s. Require all containerd namespaces/containers to lack active restart
policies; reject `always`, `on-failure`, `unless-stopped` and unknown policies.
Verify no socket/external runtime restarter and no task resurrection before starts.
Keep containerd's real unit semantics distinct from a stale source template.

### Worker access and dependency evidence

- Founders: `qualification/v3-live-systemd.json` is actual live readback. All three
  ts-orch units have Wants=containerd, no Requires/BindsTo/PartOf dependency on it;
  containerd KillMode=process, Restart=always/5s, TimeoutStop=90s, no socket trigger.
  Actual founder ts-orch TimeoutStop=60s differs from the 180s source template.
- No SSH exists to -2 workers. No key, user, permission or access was added.
  Authenticated ts-orch member/mesh state has membership/edge evidence but no
  existing systemd or arbitrary read-only node-exec endpoint.
- `v3-oci-readback.json`: all three Compute Instance Run Command plugins reported
  RUNNING. Commands had a 30-second execution cap but remained ACCEPTED with no
  content after the bounded delivery check. All three were canceled; no retry loop
  or plugin configuration change was used (`v3-oci-cancel.json`).
- **Workers: derived, not read back.** `v3-derived-workers.json` reads each exact
  OCI instance's actual launch user_data privately and compares the decoded unit
  and host-runtime script byte-for-byte with the provisioning source: all match.
  OCI image IDs resolve to AVAILABLE Canonical-Ubuntu-24.04-aarch64-2026.10.27-0.
  Unit SHA256 `eb1dec4bfc3fda17dd3d1b17c99d9d8c57f0aa4a27f9dcd698b8a83766b3574f`;
  runtime SHA256 `b7e94c8f4310a141d02ee909d4369147a92b7e7a3606195c359cb17e94ae6d17`.
  The record retains the exact boot binary and containerd/runc archive SHA256 pins.
  This verifies provisioning content and OCI image identity, not current unit
  drift, running binary digest or task restart labels. Those gates remain unread.
  Parent decision is required before treating derived evidence as sufficient.

Fresh origin refs, candidate manifests, complete logs, drill counts/times and
remaining pre-GO gates are in qualification/v3-results.md. Neither disabled CI nor
local green Fast means green deployed main; ship via ts-ship only after explicit
GO, then require both exact main revisions' real CI green before maintenance.
