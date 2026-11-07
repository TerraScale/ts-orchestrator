# Postmortem: cold-maintenance window outage, 2026-11-07

**Impact:** about 2.5 h full outage of TerraBase and the Data API in all three
regions, from 03:28 to 05:59Z (all engines stopped from 03:30:39Z, founder public
ingress closed from 03:29:19Z). The status page showed major_outage; health returned
502 on api, gru, sjc and fra. No acknowledged data was lost: no engine, data
directory, owner record or volume was changed, and the old engines restarted on
their unchanged files.

## Timeline (UTC)

| Time | Event |
| --- | --- |
| 03:01–03:03 | First window attempt aborted at the step-1 data gate (GRU follower ts-gru-2 stalled, #1141). Ingress was closed 98 s and restored. |
| 03:29:19 | Second attempt. Step 1: gate closed, probes passed, baselines recorded (GRU owner only, by decision). |
| 03:30:09–39 | Step 2. Founder containerd stopped, workers OCI-stopped (+30 s), founder engines TERM'd and exit proven. |
| 03:30:42 | **The step-2 stopped-watch gate failed** on all founders (0 samples, 0.01 s). |
| ~03:31 | The operator session (Opus) died on an API 429 before running the rollback. Engines stayed stopped and the gate stayed closed. |
| 05:49 | COS P0. The operator resumed and ran the plan's rollback. The two stale keys were deleted first (conditional DEL, tombstones read back), as the plan requires before b443 restarts. |
| 05:49:17–19 | containerd started on founders (old build). The old executor recreated the b443 engines. |
| 05:49–05:50 | Workers OCI-started on their original boot volumes. |
| 05:52–05:58 | Engines fenced (`owner: null`). The peers file still listed only the founders, so FRA's owner ts-fra-2 was "outside admitted peers" and every region's ownership check threw. The workers could not rejoin because the closed gate reset their NetBird traffic to the founders on 443. |
| 05:59:11 | Founder ingress reopened. The workers rejoined NetBird and the mesh; the peers file listed all six by 06:01:26. |
| 06:01:26 | All six engines ready at the original owners/epochs: gru ts-gru-1/9, sjc ts-sjc-1/5, fra ts-fra-2/7. |
| 06:01:33 | Canary passed in 3 regions. |
| 06:07:06 | Status operational. Health 200 on api, gru, sjc and fra. |

## Causes

1. **Single point of failure in the operator.** The window was a sequence of
   manually advanced steps. Rollback required a live operator, and nothing on the
   hosts could restore service when the operator disappeared.
2. **The stopped-watch gate had a false failure.** It required every containerd
   task directory to keep (dev, inode, ctime) equal to the baseline. When the
   stopped engine exits, its shim writes to its own bundle directory, so that
   directory's ctime moves (gru-1 `ts-5pxjeysk…`: same inode, ctime → 03:30:37Z).
   The fixtures never mutated the stopped engine's directory.
3. **The gate made rollback depend on reopening ingress.** b443 fences all regions
   while any region's owner is missing from the peers file. Workers need NetBird
   management on the founder's 443, which the gate reset. Reopening ingress after
   restart was therefore a precondition of the restart, not a step after it.
4. **The data gate did not match production behavior.** Cross-region replicas
   return 404 from the checksum API, and range hashes are incarnation-specific.
   Both were found and fixed before the attempts; the GRU follower stall (#1141) is
   a real pre-existing defect.

## Fixes (done before any rerun)

- **Dead-man switch** (`scripts/maintenance/deadman.py`, `deadman_workers.py`).
  - Root timers on every founder and a user timer on delta, every 30 s. They act
    when the window is armed and the driver heartbeat is older than 5 min.
  - Phase-aware actions:

    | Phase | Actions |
    | --- | --- |
    | `gate` | Reopen ingress. |
    | `stopped` / `installed` | Unmount clones, ensure the tombstones, restore the b443-era binary (`installed` only), start the old engines, reopen ingress. On delta: detach clones, reattach the original boot volumes, start the workers. |
    | `engines` | Finish the founder's own pinned replacement, then reopen ingress (b443 never returns over v2 writers). |

  - Dev-host fixture rehearsal with `kill -9` of the operator ×3 across all
    phases: 9/9 (`qualification/v9-deadman-rehearsal.jsonl`).
  - Live armed-idle check on the fleet: the timers fired after 306–317 s of
    staleness in phase `gate` with no effect.
- **Single detached driver** (`window.py all`). It runs every step in one process
  on beta, writes the heartbeat itself, and on any gate failure runs the same
  restore actions automatically, then verifies six-node readiness, canary and
  status. An operator-side 429 no longer stops it.
- **Stopped-watch fix.** A baseline engine task directory may change ctime but
  must keep dev and inode; any new or recreated directory still fails. New
  fixtures cover the stopped engine's own exit and a recreated engine bundle.
  Qualification ×5: both barriers 10/10 (`qualification/v9-watch-fix-qualification.log`).
- **Gate:** booted workers' VCN and public addresses may reach the founders on 443
  (NetBird management) while customer ingress stays closed.
- **Stale keys:** already tombstoned during the restore; step 4 now verifies the
  tombstones.
- **GRU:** ts-gru-2 is re-seeded as a fresh follower in-window (old data kept
  aside; rehearsed 3/3). The stale-follower readiness fix is tracked in
  TerraScale/terrascale#1141.

## Process changes

- Run windows only with model headroom. Any 429 aborts and rolls back at once;
  the driver and dead-man make that automatic.
- Every rollback path is rehearsed with the operator killed, not only the forward
  path.
