# Coordinated cold maintenance — v4, GO-ready on two parent conditions

DECISION: Replace the six-node fleet during one announced stop-the-world window.
Reason: all b443 watchers can be physically absent before deleting the stale keys
or restarting embedded NATS. A hot mixed-version installation is unnecessary.

DECISION: v3 controls workers ts-gru-2/ts-sjc-2/ts-fra-2 only through OCI Compute
instance power actions and founders through their existing pinned SSH. No worker
SSH, key or new credential. Reason: the user declined worker SSH; OCI power actions
are existing access. A STOPPED VM physically proves b443 exited there.

This supersedes deploy-plan.md and the v2 control-path gate. It is a plan, not an
execution receipt. No announce, production stop, power action, key mutation,
installation, workflow enable or rollout has occurred. The v2 sections below still
govern founders and remain the detailed gates; v4 replaces their worker paths
(offline boot-volume install; the v3 blocker is history at the end).

DECISION: Q-ZDTWORKEREXEC = 2. Install the workers offline through their boot
volumes: no worker SSH, no new credential, no new compute. Reason: the parent decided
2 after the user declined worker access; OCI volume and power actions are existing
Administrator access.

DECISION: Modify a **clone** of each stopped worker's boot volume and boot the worker
from that clone; the original volume is never written and is the rollback.
Reason: rollback is then reattaching the untouched original (exact bytes and OCID),
and the clone can be prepared while the original is being detached.

## v4 status — GO-ready on two parent conditions (2026-11-06)

All code is qualified locally and every offline step was rehearsed on real worker
clones: two runs, 18/18. No production volume, instance, process, key or publication changed.
GO requires the parent to accept both of these:

1. **A revised announced window: 20 min serving maintenance + 5 min status (25 min).**
   The worker boot, 60 s watch, stage and replace chain runs after the founder
   control-plane restart. The measured and estimated budget below ends near
   t0+1030 s (≈17 min), so the current 12 min hard limit does not fit.
2. **Accept two worker steps qualified without a production rehearsal.** A boot-volume
   swap on a STOPPED instance (detach the original, attach the clone as boot) and the
   first boot of the offline-installed volume cannot be rehearsed without a new
   instance, which the parent excluded. They are covered by the Slow drill and
   boot-drive harness below. If either fails, the worker reattaches its original
   volume (per-worker rollback).

Unchanged pre-GO and in-window gates: ship via ts-ship only after GO, BUILD green on
both exact shipped main revisions, and the v2/v3 founder gates.

### v4 offline worker install — what was built (local commits, not shipped)

- `ts-orch bootstrap-maintenance pins-offline --root MOUNT` reads the stopped
  worker's own Swarm agent DB (`/var/lib/ts-orch/swarm/worker/tasks.db`). It selects
  the single assigned, desired-RUNNING, regional TerraBase task; retained SHUTDOWN
  history is ignored (found on the real clone). The pin uses the executor's own
  fingerprint.
- `bootstrap-maintenance arm-offline --root MOUNT --manifest M` refuses when:
  - the root is `/` or not a separate mount;
  - the volume's `/etc/hostname` is not the manifest member, or is this host;
  - the process identity is not the unreachable `PID 1<<22` sentinel (exit is
    proven by the detached volume itself);
  - the manifest source differs from the agent DB pin.

  It then writes the existing fence journal and owner ingress hold, and moves
  `tasks.db` aside to `zdt-retained/` so `worker.Init` cannot restart b443 at boot.
- `cold.py offline-install` (on the founder) refuses when the mount is wrong, the
  binary or old binary hash differs, or a pending `release-trial` (probation could
  restore `.prev`) is present. It then:
  1. Runs pins-offline and arm-offline.
  2. Installs the new binary atomically (old one kept as `.zdt-b443`).
  3. Installs `cold.py` and the oneshot `ts-orch-cold-drive.service`, enabled.
  4. Writes `drive.json` with job ID, member and **worker instance OCID**.
  5. Writes a hash/mode receipt.

  `offline-verify` recomputes the receipt.
- **Worker boot drive** (`cold.py boot-drive`, runs once:
  `ConditionPathExists=!attempted` + O_EXCL):
  1. IMDS instance ID must equal `drive.json`. A founder that boots a same-label
     clone root is refused.
  2. Wait for the executor socket.
  3. 60 s rebooted watch: no engine process or live engine task.
  4. `stage`, retried ≤300 s until the worker has joined the mesh.
  5. Best-effort `prepull` of the pinned target, ≤300 s.
  6. Followers only: poll the read-only `owner` action ≤900 s.
  7. `replace`, then status must read `verified`.

  The 60 s driver budget starts only at `replace`. A follower's `replace` never
  runs before its owner is a ready writer **and** has released the founder's ingress
  hold.
- Orchestrator fixes found while building this, needed for any cold bootstrap:
  - **Staging uses Parallelism 0** for the fenced founder's TerraBase apply only
    (`BootstrapStage`). With Parallelism 1 + STOP_FIRST, the updater picks a random
    slot and could wait on the follower while the owner must go first. That
    reproduced 1/5 in the Slow drill and would deadlock about half the regions.
    Normal publications stay fenced, and the next normal apply restores 1.
  - Edge `owner` action: read-only, outside the barrier lock, 10 s probe.
  - Executor `prepull` of the held job's target.
  - A held, never-started down-node replacement task completes Shutdown as a no-op.
    Swarm's agent already fails it out; this is now explicit.

### v4 qualification evidence

- **Rehearsal on real clones, two runs × 3 per region, 18/18 PASS**
  (`qualification/v6-offline-rehearsal-{a,b}.json`). Run A used candidate `dfa83761…`;
  run B used the final `2ccab3fd…` with verify-rw and the instance-OCID drive binding.
  - Each repeat:
    1. Fresh clone of the live worker boot volume, attached rw to its founder.
    2. Mount, then capture pins and cross-check against the manager's running task.
    3. offline-install, verify-rw, unmount, detach.
    4. Reattach read-only, `offline-verify`, detach, delete the clone.
  - Every founder was checked clean after each repeat (`/`, `/boot`, `/boot/efi` and
    the by-label links on `sda`). No clone, attachment or staging dir remains.
  - Seconds, min/median/max:

    | Step | Seconds |
    | --- | --- |
    | Clone | 12.0/12.9/21.2 |
    | Attach rw | 17.5/20.5/37.8 |
    | Mount | 1.0/3.0/3.6 |
    | Capture | 1.0/5.5/6.3 |
    | Install | 7.8/10.1/10.6 |
    | Unmount | 0.5/2.7/2.9 |
    | Detach | 19.8/33.1/37.3 |
    | Reattach ro + verify | ≤50 |
    | Delete | 3.9/7.0/11.7 |

  - **Forward path, clone→detach: 73–119 s per worker (run A); 78–103 s including
    verify-rw (run B)**; regions run in parallel. Report:
    `benchmark/bench/2026-11-06-zdt-offline-worker.md`.
- Slow drills ×5 each: the six-node fence drill and the new
  `TestOfflineArmedWorkerRebootsFencedAndReplaces`. The latter uses a real manager,
  dispatcher, Raft and agent, with fake runtime and edge:
  1. The worker is powered off until DOWN, and Swarm creates a replacement b443 task.
  2. Arm offline; the agent DB is gone at reboot.
  3. Both the pinned and the down-node b443 tasks stay unstarted.
  4. Replace with the sentinel identity verifies, and the founder is untouched.

  Mutation check: without the offline fence the drill fails.
- Fast suites for the touched packages, vet, the boot-drive harness ×5, and the edge
  owner test (including refusal at another epoch or while the owner still holds
  ingress). Logs: `qualification/v6-qualification*.log` (final: Fast per package
  ≤12.5 s; offline drill 7.9–9.7 s).
- Independent Opus review: no path starts b443 or a second writer. Its six findings
  (staging and race stalls, barrier lock, boot-drive retries and prepull, label
  reboot hazard, verify-before-boot) are fixed or gated here.

### Founder hazard while a clone is attached (gate)

Worker clones carry the same filesystem LABELs (`cloudimg-rootfs`, `BOOT`, `UEFI`)
as the founders. While a clone is attached, the founder's `/dev/disk/by-label/*`
point at the clone (observed). A founder boots with `root=LABEL=cloudimg-rootfs`,
so **a founder must not reboot while a clone is attached.**

- Gate before every attach: no `/run/systemd/shutdown/scheduled`, no
  `Automatic-Reboot "true"`, and `/`, `/boot`, `/boot/efi` and the by-label links on
  `sda`. Re-check after detach. `reboot-required` exists on founders and is
  ignored, because nothing reboots automatically.
- Attach for ≤2 min per worker. The IMDS check means even a mistaken founder boot of
  the clone cannot drive.

### Verified for v3 (read-only, no production mutation)

- **OCI get-instance**, 2026-11-06T10:19:38–44Z, `qualification/v5-oci-worker-instances.json`:
  ts-gru-2, ts-sjc-2 and ts-fra-2 are RUNNING. Each is VM.Standard.A1.Flex with
  2 OCPU and 12 GB in AD-1, recovery-action RESTORE_INSTANCE. Each has one ATTACHED
  boot volume and no block volumes, so worker data lives only on the boot volume.
  user_data SHA256 is unchanged from the v3 derivation. Our DEFAULT principal is
  in Administrators (`manage all-resources IN TENANCY`), so power actions are
  allowed by policy. They have not been exercised.
- **Embedded NATS quorum without workers:** the JetStream meta group has exactly
  3 peers, and all three founders host the same three R3 KV raft groups
  (`terrabase-homes`, `terrabase-region-owners`, `tb-clock-skew`). Workers connect
  only as routes or clients. Step 4's conditional DELs therefore keep quorum with
  all three workers powered off.
- **Founder data inventory:** each live b443 engine has exactly one data mount,
  `/var/lib/ts-data/terrabase`. `terrabase-e2e` (SJC/FRA, 2026-10-23), `m1-test`
  and the `netbird*` trees are not engine mounts and are out of DB-backup scope.
- **Measured founder backup, real bytes,** `qualification/v5-founder-backup-real.{py,json,log}`.
  Three repeats per founder streamed a live `tar` over root SSH stdout with
  compression off to pinned mariogk-dev, then hashed and discarded it. Source and
  destination SHA256 matched every time, and nothing was stored.

  | Founder | Real TerraBase bytes (files) | Live archive bytes | SSH transfer and readback | Archive and hash on founder |
  | --- | ---: | ---: | ---: | ---: |
  | ts-gru-1 | 37,220,812 (112) | 37.7–38.1 MB | 1.26–1.50 s | 0.05–0.06 s |
  | ts-sjc-1 | 13,931,292 (61) | 14.5–15.5 MB | 5.28–5.47 s | 0.02–0.05 s |
  | ts-fra-1 | 9,700,662 (76) | 10.1–11.1 MB | 5.08–5.20 s | 0.02–0.04 s |

  SJC and FRA are dominated by SSH session latency, not bytes. The budget is
  `ceil(1.5 × (transfer + 2 × founder archive/hash + the v4 dev copy/encrypt/readback rate scaled to real bytes))`, computed per repeat:
  **GRU 5 s, SJC 10 s, FRA 9 s**. The largest parallel node is 10 s, well inside
  the reserved 150 s. Refresh sizes at preparation. Repeat the rehearsal if any
  root exceeds 2× these bytes.

### v4 sequence (t0 = gate close; founder steps as v2/v3)

Prepare, before the window:

- Capture each worker's running TerraBase task (manager `service ps`) and the owner
  records. Build each worker manifest: local job from the expected pins with
  `process {pid: 4194304, start: 1}`; owner job is the founder's prepared job for
  GRU/SJC, and itself for FRA.
- Stage the exact green binary (hash) and `cold.py` in `/var/tmp/zdt-offline` on each
  founder (root, 0700; `/run` is noexec).
- Pass the founder reboot gate.

In the window:

1. Announce and close ingress (≤75 s), as v2.
2. Stop all six engines (≤180 s), as v3 2a–2c: founder containerd first, then worker
   OCI SOFTSTOP→STOP, then founder TERM→KILL and the 60 s watch. Gate: 3 founder
   receipts plus 3 OCI-STOPPED receipts (`cold.py oci-stopped`; `watch-check`
   accepts this mix).
3. **Workers W1–W5, in parallel with founder steps 3–5 (measured 73–119 s +
   verify ≤12 s):**
   - **W1:** clone the STOPPED worker's boot volume.
   - **W2:** in parallel, detach the original boot volume from the worker (keep it).
   - **W3:** attach the clone rw to its founder and mount it. `pins-offline` must
     equal the prepared pin.
   - **W4:** offline-install, then **offline-verify on the rw mount**. Both
     receipts are required.
   - **W5:** unmount, detach, re-check the founder's by-label links.
4. Founder steps 3–5 as v2: backup (budget ≤10 s), delete the two stale keys,
   arm-stopped, install, restart, and the 60 s restarted watch on the founders
   (≤500 s).
5. **W6:** only after step 5 passes, attach the clone as the worker's boot volume
   and OCI START it (estimate ≤160 s to ts-orch ready; unrehearsed). The drive then
   runs: watch 60 s, stage, prepull.
6. Engines at the same owners and epochs (≤60 s budget each):
   - **SJC and GRU:** the operator drives the founder owner (`replace`) as soon as
     stage succeeds. The worker follower's drive then passes `owner` and replaces
     itself.
   - **FRA:** the fra-2 drive replaces the owner. The operator waits for
     `bootstrap-maintenance owner` to pass on fra-1, then drives the fra-1 follower.
   - The outcome is read through the founder's manager tasks and edge status. A
     worker's own receipts are readable only by stopping it and attaching
     read-only.
7. Reconcile, canaries, reopen and status, as v2 step 7.

Budget: worker START ≈ t0+500 → ready ≈ +660 → watch/stage/prepull ≈ +760 → owners
≈ +820 → followers ≈ +880 → reconciliation ≈ +960–1030 s. Hard limit with the
revised window: 1200 s serving.

### v4 per-worker abort and rollback

- **Before START** (W1–W6 fail, a receipt is missing, or a founder gate fails):
  - Detach the clone and reattach the **original** as boot; do not start it.
  - Optionally retry once on a fresh clone if the window allows.
  - Otherwise use the fleet rollback. No v2 engine can have started in that region,
    because stage needs both nodes fenced.
- **After START, before replace** (the watch, stage or owner wait fails; the fence
  holds and the budget is unspent):
  - STOP the worker and attach the clone read-only to its founder to read the
    drive receipts.
  - Either re-drive once (rw mount: remove only `zdt-drive/attempted`, verify, reboot
    the clone), or roll back.
- **Rollback for a region:**
  1. Stop all v2 engines in the region and prove they exited.
  2. STOP the worker, then detach the clone and reattach the original.
  3. Start b443 on the founder per the fleet rollback, then START the worker. Its
     original volume restarts b443 from its own agent DB.

  Never START an original (b443) volume while that region runs any v2 writer.
- Keep the originals until the separately approved cleanup after success; the
  clones become the workers' boot volumes.

## GO attempt 2026-11-06 — aborted at the pre-window publication gate (12:50Z)

GO was received with these conditions: a 20+5 min window announced first; the sjc
worker canary first; SOFTSTOP→timeout→STOP; ts-ship both repos first; per-step UTC
reports. The attempt stopped before shipping or announcing anything. No production
change was made.

- **ts-orchestrator CI is active, not disabled.** "TerraScale Orchestrator Go
  checks" (`ci.yml`) runs `deploy/release-push` on every push to main with a
  required publication. A ts-ship of this candidate would hot-push the new ts-orch
  to all six nodes while b443 runs: the forbidden mixed install and NATS restart.
  A `workflow_dispatch` run builds and publishes `ci-<sha>-run-<id>` without
  release-push, but only if the workflow is disabled across the ts-ship push.
- **The monorepo has no build/release separation.** CI's `main` job builds the
  engine image and runs "Release to every region" in the same job, for both push
  and dispatch. The fenced founders retain the authenticated candidate only from
  that release (`mesh/release.go` → `RetainCandidate`), so it must land after
  step 5. Measured push→release on run 42111952116: 7 min 23 s. This puts about
  8 min of CI, plus queue variance, on the in-window critical path, giving a
  ≈t0+1190 s finish against the 1200 s limit with no margin.
- Neither origin/main moved (ts-orchestrator `2142b1f3`, terrascale `a811367b`);
  no other lane pushed.

## GO attempt 2 (Q-ZDTPUBLISH = 1), 2026-11-06 — aborted before step P1

Nothing was disabled, shipped, dispatched or announced. Option 1 cannot work
because the fence pins the target **image digest** before the window, but CI
produces that digest only inside the window:

- `arm-stopped` and `arm-offline` manifests must carry `Target.Image` as
  `ghcr.io/terrascale/terrabase@sha256:<arm64>`. The job validator and the
  cross-checks all compare that exact digest: `store.go:120/383`,
  `bootstrap_cold.go:72`, `mesh/bootstrap.go:58/73`.
- The fenced founder records the authenticated candidate only if
  `j.Target.Image == released image` (`candidate.go:31`). Otherwise the release is
  refused, and a failed push-run release dispatches a fresh main run, which
  rebuilds a new digest.
- The monorepo `main` job builds the image and releases it in the same job, for
  push and dispatch alike. No green digest can exist before step 5 without a
  release reaching unfenced b443-era executors.

## Option 2 artifacts — GO-ready for the window (2026-11-07T01:57Z)

The monorepo CI split shipped. A `publication` dispatch input takes `build-only`
(TerraBase images, no release, `:main` unmoved, own concurrency group) or
`release-only` with `terrabase_arm64` (no build; the label must equal the main
revision; one region per call; each region must report `done`). An independent
review found no blocking issue; its findings are fixed (5b116808c). CI and the
ts-orch Go checks stay `disabled_manually`; each dispatch was enable→run→disable.

**Pinned artifacts (write into every fence; main must not move until release-only):**

- TerraBase: monorepo main `d79589c6b9f5bfa2f685c56cabe88a16b0c3223b`, build-only run
  42326073891 (green; release step skipped).
  - **Target.Image** = `ghcr.io/terrascale/terrabase@sha256:0046773223695fdc4c26043f8fa843d89a394465c8a84c1bc6e0e9fb1b05c001`
    (arm64 child)
  - Index: `sha256:e411c1d2083b6f07020cbcbce952d17c9adcdf3b491f3f8586efa2f393e5f156`
- ts-orch: main `09381c305b0aedcc12cd3a7e046a72d38ce8d58c`, build-only run 42324265546
  (green; release-push skipped), release `ci-09381c30…-run-42324265546`.
  - arm64 `27b17d84026fca3153969bed61fd25cfef68990978488199fc1672308215a3c2`
  - amd64 `e93bf083b4b55e282db6026a279d756bad83af38a58aff8ad4df4ff9b88c801c`

**Fixes required to reach green**, all shipped via ts-ship:

- ts-orch:
  - SwarmKit provenance digest (8bd5ee901 patch).
  - GO-2026-6888 / GO-2026-6865 (brotli 1.2.7, compress 1.20.2, including the
    vendored SwarmKit graph).
- Monorepo:
  - Whitespace format fix.
  - Dashboard runtime base re-pinned for USN-9001-1.
  - Engine brand removed from the bootstrap harness, which moved to
    `scripts/terrabase/`.
- One CI flake re-run (natscell test port collision).

**Window:** 30 min serving + 5 min status. The release-only dispatch adds its CI
queue and runtime after founder step 5, on top of the ≈t0+1030 s budget, so
20 + 5 has no margin.

**Read-only audit (01:00Z, sjc-1):**

- Stale keys `home.…03` seq 78672 and `home.…04` seq 78674: both `ts-sjc-2`,
  epoch 3, home sjc.
- Owners:
  - SJC `ts-sjc-1` epoch 5
  - FRA `ts-fra-2` epoch 7
  - GRU `ts-gru-1` epoch 9

Revisions and hashes must be re-read at preparation.

**Open items before the announcement:**

- The status-page admin session cookie is a user-only secret; it will be requested
  via a secret card.
- **The GitHub token of the MarioGK gh login was printed in a session tool output**
  when `ts-dev-secret env` was misused on a raw token. Revoke and re-login before
  the window.

## Window attempt 2026-11-07 03:01Z — aborted at step 1 (data gate), restored 03:02:48Z

**Preparation (02:48–03:00Z, all PASS):**

- Exact artifacts staged on the founders: orch `27b17d84…`, cold.py `87fe0ce0…`.
- Founder pins equal the live container labels.
- Runtime restart labels pass; fresh task baselines captured.
- Stale-key audit and dry-run pass (seq 78672/78674).
- Gate `nft --check` passes on all founders.
- Canary passes: token, writes via gru/sjc/fra, all reads 3/3.
- Live peer status: gru `ts-gru-1`/9, sjc `ts-sjc-1`/5, fra `ts-fra-2`/7 writer.

**Data-gate design corrections found against production:**

- Cross-region replicas return 404 from the checksum API, so each region uses its
  home catalog only.
- Range `hash` values differ between a region's two nodes even for identical rows
  (incarnation-specific), so equality uses table, rowid bounds, rows and bytes.

**Window:**

- 03:01:10Z: gate closed on 3 founders (negative and positive probes passed).
- 03:01:38Z: settled.
- 03:02:38Z: **GATE FAILED.** The GRU founder (owner) and the gru-2 follower differ:
  - ts-auth (`rate_limits` 284/249, `closure_commits` 41/36, …)
  - ts-dashboard (accounts 44/39, …)
  - the 02:53Z canary DB is absent on gru-2.
- 03:02:48Z: gate removed (founder public ingress was closed ~98 s).
- 03:02:53Z: canary passes in all regions.

No engine, key, volume or controller was touched.

**Pre-existing blocker:** gru-2 reports `ready: true` as follower at gru-1/9, but
its ts-auth replica is at revision `…:3:0` while the owner is at `…:556:191`.
GRU replication to its follower is stalled, so GRU has no current standby. The
cold plan's follower prime and catch-up would run against a broken replication
path, so no retry until that is diagnosed and fixed (or GRU's follower is
explicitly re-seeded).

## Q-ZDTGRUREPL = 2: re-seed ts-gru-2 in-window (2026-11-07)

DECISION: re-seed ts-gru-2 as a fresh follower. In W4, after offline-install,
move its `/var/lib/ts-data/terrabase` aside on the clone to
`terrabase.stale-zdt-20261107` (kept on the clone; the original boot volume also
keeps it). Leave an empty data dir with the original owner and mode. The v2
engine starts on it as a fresh follower, and the bootstrap verify's
`/v1/rollout/prime?source=ts-gru-1` runs `SyncCatalogsAsync` + `PullAllAsync`
from the verified owner before verify can pass.
Reason: ts-gru-1 is authoritative. Copying the owner's files would duplicate the
owner's incarnation onto another node, and an empty data dir is the engine's
supported fresh start.

**Data gate:**

- Before the stop: GRU checks the owner only; SJC and FRA require founder ==
  worker.
- After the window: every region requires founder == worker (this proves the
  re-seeded follower is fully primed), and founder after == before.
- Equality covers table, rowid bounds, rows and bytes per range; range hashes are
  incarnation-specific.

**Issue:** TerraScale/terrascale#1141, "b443 follower reports ready while stalled
(ts-gru-2 ts-auth rev 3 vs 556)", filed with evidence.

DECISION: d79589c6 `NodeReadiness` does not check follower freshness either.
The stale-follower readiness rule and its drill ship after the window as the
first v2 rolling update, not in this window.
Reason: a correct rule needs the stall's root cause, which is unknown (no worker
shell; the retained data dir allows offline inspection). It also needs review
and a new digest under the main freeze. In this window, the re-seeded follower
is guarded by prime pull-all and the post-window two-node gate.

**Re-seed rehearsal: ts-gru-2 clone path ×3, 3/3 PASS** (170 files, 23–29 MB moved in 0.5 s; owner 65532:65532, mode 755; founder clean); results in
`qualification/v8-reseed-rehearsal.json`.

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
- Use the actual founder systemd readback and the conditionally accepted worker
  provisioning/image derivation; do not claim worker units were read back. The
  parent accepts that derivation only with the scripted 60-second gates below.
  Before GO verify the accessible dependency graph: stopping containerd
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

### 2. Stop TerraBase on all six, with no automatic recreation (conditional; HOLD)

**v3:** workers use OCI power actions (v3 step 2b), and founders use the steps below.

**Unexecutable until the control-path gate above is resolved.** The following
explicit systemd/PID commands require approved worker access; no existing Swarm
CLI can replace them. No fleet-wide service-removal intent is published.

Keep old ts-orch/NATS running for the moment, but stop the containerd control
service on **all six** hosts first. Verify every runtime API is unavailable and
cannot restart automatically. This prevents the old executor from creating new
TerraBase tasks while the existing embedded NATS quorum remains available for
step 4. Do not restart ts-orch or NATS yet.

Signal TERM to each captured TerraBase host PID only after rechecking its start
ticks and executable identity. Do not call the legacy /drain endpoint. Wait for
physical exit and listener closure on all six; record PID/start identity, UTC exit,
container/shim state and absence of replacement PIDs. Run `cold.py watch` for
60 full seconds on every node after the stop, with the retained pre-stop task
baseline and `--barrier stopped --runtime-down`. Run `watch-check` over all six
receipts before step 3/4: abort=true, unreadable/incomplete/missing/wrong-barrier
receipt or any new engine PID/containerd task aborts the window. A failed API request, failed
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
holds and zero running TerraBase processes. Repeat the full 60-second scripted
watch on all six with `--barrier restarted` (runtime API now required readable),
then consume all six receipts with `watch-check` before any engine start. The
pre-stop baseline forbids new/recreated task identities, including non-engine
tasks. A reappearing b443/terrabase process, new task or failed receipt aborts.
Do this again after any additional stop/restart; an earlier receipt is not reusable.

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
| Runtime APIs down, six exact engine PIDs physically gone; six 60 s stopped-watch receipts pass | 180 s | Stop advancing; no NATS restart/key change/new process. Account for stuck host. |
| Cold local + encrypted off-host backup readback | 330 s maximum; measured budget required before GO | Leave originals untouched; complete safe two-key cleanup before b443 watcher restart. |
| Both exact conditional tombstones read back | 350 s | Reconcile each private receipt; no blind retry/reinsertion; keep engines absent until both hazards are gone. |
| Six fences, offline controller snapshot, new ts-orch/NATS up; six 60 s restarted-watch receipts pass | 500 s | Keep gate; fleet retained-state rollback, excluding JetStream. |
| Six exact new engines at original owner/epoch, replicas caught up | 650 s | Fleet rollback after physical exit and six-second exclusive TTL. Each local replace also retains its independent 60 s bound. |
| Logical reconciliation, token issuance, all nine canary reads; reopen | 720 s | Reclose/retain gate and rollback against latest retained acknowledged data. |
| Five minutes passing checks and operational status | 1020 s | Report measured incident; never override measured component status. |

The cold-backup budget includes full local copy/encryption/readback and off-host
transfer/readback. Before GO, measure **real DB bytes on each of the six nodes**,
time an equivalent-size copy over that node's actual planned transfer path, and
set its budget to **ceil(measured seconds × 1.5)**. Record the largest parallel
node budget and demonstrate that it fits the currently reserved 150 seconds;
otherwise obtain a revised window before maintenance. The fixed helper alarm is
a maximum, not a substitute for the measured +50% budget. Worker measurement
is currently blocked by the same access prerequisite; founder-only/dev-link
numbers are not six-node qualification. A small dev fixture is not evidence that the
production inventory fits. If it does not fit, the parent revises the announced
window before closing the gate. If physical exit is unprovable or quorum is down,
a hard abort does not magically make rollback safe: retain maintenance and report
at once rather than launch a conflicting old writer to meet the clock.

The exact stop tool pins a PID/start/executable and uses a pidfd; TERM20s → KILL5s,
outer28s. Require all containerd namespaces/containers to lack active restart
policies; reject `always`, `on-failure`, `unless-stopped` and unknown policies.
Verify no socket/external runtime restarter and no task resurrection before starts.
Keep containerd's real unit semantics distinct from a stale source template.

### Fixed-duration no-reappearance gate qualification

`scripts/maintenance/cold.py` now implements `watch-baseline`, `watch` and
`watch-check`; README has their exact local commands. Every observation starts
with an abort receipt; the completed 60-second watch alone can record pass.
`watch-check` consumes six distinct-node receipts and refuses missing, aborted,
incomplete or wrong-phase receipts. Stop and restart receipts cannot substitute
for one another. Both barriers ×5 pass10/10,60.0079–60.0146s, including critical
refusal cases on real processes and shim task directories in private namespaces.
Runtime replies in these tests are contract fixtures; actual parser readback passes
on all three live founders. This is local qualification, not physical exit proof
from live workers. `qualification/v4-watch-proof.json` records exact source hashes.

### Read-only founder backup-path measurements (partial)

**Superseded by the v3 real-byte measurement** (`qualification/v5-founder-backup-real.json`); kept for history.

`qualification/v4-founder-backup-path.json` and
`benchmark/bench/2026-11-06-zdt-cold-gates.md` retain three measured repeats per
founder. Real file bytes: GRU26,780,425; SJC24,134,351; FRA10,896,355, only the
principal `/var/lib/ts-data/terrabase` root. Proxy local copy/encrypt/readback plus
actual source→mariogk-dev SSH transfer/readback yields +50% budgets4s/11s/9s.
The full random equivalent stream's source and destination hashes/lengths agree.
Pin **mariogk-dev** as off-host destination and root SSH stdout with compression
**disabled** for the actual encrypted archive, or repeat on the changed path.
The local filesystem copy timings are from dev, not production. Worker roots
and additional mounts remain unmeasured. Refresh every size before GO; a larger
inventory requires another equivalent-size rehearsal. This is partial evidence,
not permission to start an outage or assume worker backups fit the budget.

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
  Parent accepted the derivation conditional on the two scripted 60-second
  zero-engine/no-new-task gates. Live restart-label readback and actual stop/backup
  execution paths remain prerequisites; the conditional acceptance grants no access.

Fresh origin refs, candidate manifests, complete logs, drill counts/times and
remaining pre-GO gates are in qualification/v3-results.md. Neither disabled CI nor
local green Fast means green deployed main; ship via ts-ship only after explicit
GO, then require **BUILD green on both exact shipped main revisions** before
maintenance. Slow **PROBES are not deploy gates** under the parent's decision.

## Superseded v3 blocker, sequence and rollback (history)

### v3 status — NOT GO-ready (2026-11-06T10:40Z)

**Exact blocker: steps 5–7 need root on each worker, and v3 has no path to it.**
OCI instance actions change only power state. Each of the following runs locally as
root on the host it changes. None can run on a worker without worker execution:

1. Installing the new ts-orch binary. The worker boot volume holds the old binary.
2. `bootstrap-maintenance arm-stopped`, which needs root, the local hostname and the
   local containerd socket.
3. `stage`/`replace`, which use the executor's local unix socket
   (`internal/app/bootstrap_cli.go`, `RunBootstrapMaintenance`).
4. The restarted-barrier 60 s `cold.py watch` receipts.

v3 step 6 assumed workers "come under the new executor" on boot. That does not
hold. START boots the unchanged boot volume, and the enabled old unit
(`ExecStart=/usr/local/bin/terrascale-orchestrator`, `Restart=always`) runs the old
binary. Its user_data is a once-per-instance `#!/bin/bash` with no per-boot hook,
so it does not reinstall anything. At boot the old Swarm agent's `worker.Init`
starts a task manager for every locally assigned task before it contacts any
manager (`third_party/swarmkit/agent/worker.go:82-111` at 2142b1f). It is unproven
whether b443 then passes its local storage checks. Either way the worker stays
under the old executor. Stopping the VM again repeats the identical boot, so the
remedy never converges.

**FRA's retained owner is ts-fra-2 (FRA2, epoch 7).** Without a worker executor,
FRA cannot start the new engine at the same owner and epoch, and owner CAS is
excluded. The GRU and SJC followers (ts-gru-2, ts-sjc-2) have the same gap.

Alternatives checked read-only:

- **OCI Run Command:** no policy grants `instance-agent-command-execution-family`
  to any dynamic group. That explains why the v3 commands stayed ACCEPTED with no
  output. user_data also adds no `ocarun` sudoers, so even an IAM grant would not
  give root.
- **ts-orch self-update:** this reaches a worker only through a release publication
  to its old executor, after `worker.Init` has already run. That path is unreviewed,
  and publications are held.

Next decision for the parent:
`NEED Q-ZDTWORKEREXEC: worker root for steps 5–7 | options: 1) approve the bounded
temporary worker SSH key from Q-ZDTCONTROL (only reviewed path; everything else
in v3 is measured) 2) build, review and qualify an offline boot-volume path (stop,
detach the boot volume, attach it to the same-AD founder, install the binary and
fence, reattach) plus boot-time stage/replace. That is new code and adds minutes
per worker to the window. 3) OCI Run Command needs a new IAM grant and root
sudoers, so it needs option 1 first.`

### v3 sequence (founder SSH and OCI only; t0 = gate close)

Prepare-section rules apply to founders unchanged. For workers, preparation adds:

- Save the OCI get-instance readback with lifecycle RUNNING, the ETag and the boot
  volume OCID.
- Read the six TerraBase tasks and their node pins from the founder Swarm managers.
- At the drained cutoff, read each region's owner and follower applied positions
  through the existing authenticated TerraBase/ts-orch status.

There is no worker backup. By parent decision, worker files stay untouched on the
boot volume. For FRA the owner copy is on ts-fra-2. The **fra-1 follower must equal
fra-2's applied positions at cutoff**, otherwise abort before any stop. The same
holds for the gru-2 and sjc-2 followers against their owners.

1. **Announce and close ingress** as in v2 step 1 (≤75 s). Abort and rollback are
   unchanged.
2. **Stop everything, follower-safe and executor-first** (≤180 s):
   - a. On the 3 founders, stop containerd and verify the runtime API is down and
     cannot restart. Do this before any worker power action, so a founder executor
     cannot re-place a worker task when the worker node disappears. Keep old
     ts-orch and NATS up.
   - b. Send OCI `SOFTSTOP` to the 3 workers in parallel, each with `If-Match` on
     the saved ETag. Read back with bounded `get-instance` until `STOPPED`. At
     90 s, send `STOP` (hard). On shutdown the old ts-orch cancels its agent and
     does not stop workloads (`swarmruntime/node.go:291`). systemd's final
     SIGTERM→SIGKILL reaches b443 with no `/drain`, the same signal path as v2.
     **Unverified pre-GO:** whether OCI accepts `STOP` while the instance is
     `STOPPING` from `SOFTSTOP`. `SOFTSTOP`'s own forced power-off comes after
     15 min, which exceeds the window. This cannot be qualified read-only.
   - c. On the founders, TERM→KILL the pinned engine PIDs (TERM 20 s → KILL 5 s,
     outer 28 s), then run the 60 s `--barrier stopped --runtime-down` watch.
   - Gate: 3 founder watch receipts plus 3 OCI `STOPPED` readbacks with
     instance-id, time and ETag. Founder evidence must also show the worker NATS
     routes and NetBird peers gone. **Pre-GO code gap:** `cold.py watch-check`
     accepts only six local receipts. It needs an OCI-stopped receipt type.
   - Abort: a worker not `STOPPED` by 150 s, or any founder engine alive. Retain the
     gate, delete no keys and restart no NATS. Report the host.
3. **Founder cold backup** as in v2 step 3, founders only. Measured budget is
   ≤10 s per node in parallel, with a 330 s hard limit.
4. **Delete the two stale keys** as in v2 step 4. Quorum is founders-only, as
   verified above.
5. **Founders:** `arm-stopped` with the 3 founder manifests, final controller
   backup, install the new ts-orch, restart containerd and ts-orch, then the 60 s
   restarted watch on all 3 founders.
6. **START the workers** after step 5 passes. **BLOCKED:** a worker boots its old
   executor (see the blocker above). With worker root this becomes: install, arm,
   then a 60 s restarted watch per worker before any engine start.
7. **New engine at the same owners and epochs:** SJC (sjc-1 owner), FRA (fra-2
   owner, **BLOCKED**), GRU (gru-1 owner), each followed by its follower. The
   remaining checks follow v2 steps 6–7.

### v3 rollback (existing access only; executable at any step)

1. Retain the gate.
2. Stop the new controllers and engines on the founders, and prove PID exit.
3. Keep both stale-key tombstones. Restore the old founder binary and controller
   state offline (v2 B).
4. Start b443 on the founders' retained files at the unchanged owner and epoch.
5. OCI `START` the workers. Their old executor restarting b443 from local agent
   state is the intended rollback here: the data is untouched, the owner and
   epoch are unchanged, and the stale-key hazard is already deleted.
6. Verify one writer per region, FRA served by fra-2, then run canaries and reopen
   ingress.

Never START a worker while a v2 engine runs in its region. A worker that fails to
reach RUNNING within 10 min stays in maintenance. Report it; do not CAS its owner
away.

Target: 10–15 minutes of serving maintenance. The current hard serving limit is
12 minutes; status resolution can take another five consecutive passing minutes
(17 minutes total). The notice and final GO must reflect these bounds. Preparation
and artifact production happen before that clock. If the estimate stops fitting,
start the rollback while its original processes/data are still available; do not
wait indefinitely for CI, backup transfer, readiness or a missing node.


## Superseded v2 control-path gate (history)


The installed SJC founder binary is clean source `2142b1f308b1c1169d25093f93eab3b10c479e1c`
(`vcs.modified=false`), SHA256
`214b1e2791692bca33e9b6d9b554aab9346aaabba034285606e865d6703c4146`.
Its real `service --help` includes **`ts-orch service rm <name>`**. This is an
existing fleet-wide desired-state removal, not a scale-to-zero command; apply
rejects replicas 0. Do not execute `service rm terrabase` in production.

Disposable qualification against that exact installed source passed the actual
CLI `apply -f`, `ls`, `ps`, `rm`, and final task-lifecycle convergence. A separate
real three-region embedded NATS fixture passed the actual `mesh.Remove` wrapper
used by fleet CLI removal. These prove command availability and dispatch, not a
physical six-node TerraBase stop. Only the disposable lifecycle/appliers and
TerraBase HTTP contract are fixtures; no TerraBase binary was downloaded or run.

**That installed path cannot satisfy step 2.** Its executor calls `DrainTask`
before TERM; mounted-data removal calls the same `stopTask`. The regional edge
requires another admitted, ready surviving writer. Exact-source HTTP contract
drills prove refusal both when the last node is the sole admitted peer and when
its still-admitted peer is unavailable (`regional prime HTTP 503`). Generic CLI
success/removal acknowledgement is not physical exit. Removing both nodes may
also start the legacy handoff we are avoiding. `member drain/leave` uses this
same lifecycle and does not provide the missing cold-stop bypass.

DECISION: Keep the production window held; do not substitute service removal for
physical stop. Reason: the installed controller cannot stop the last regional
writer through that path, and the new pinned bypass is not installed yet.

The fallback is **a user-approved temporary SSH key on the three workers**, as
specified in Q-ZDTCONTROL. No new key, security permission or access is authorized
or installed. Until that approval and bounded installation/readback, steps 1–7
are not executable: no maintenance publication, stop, key deletion or rollout.
The temporary access must also support per-node byte inventory, backup transport,
and the two process-watch receipts; derive-only units do not grant execution.
Proof: `qualification/v4-installed-control.md` and its exact-source fixture/logs.
