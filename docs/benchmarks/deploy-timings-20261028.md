# Deploy timings, 2026-10-28

Target (2026-10-21): every green main build deploys itself to gru, sjc and fra
in 60 s or less per region, and an app deploy takes 10 s or less on a warm host.

Every number below comes from a real production release. They are read from the
per-region rows that `release app`, `release mesh-check` and `release push` print
in the GitHub Actions logs: `pulled`, `submitted`, `ready` and `bake` are
cumulative times from the start of that region's turn, and the total is the
region's `elapsed_ms`. A region's own time excludes waiting for the earlier
regions' bakes (the rollout order goes one region at a time).

## Before: 5-minute bake (until #200)

| Release | Run | Region | Total | Pull | Ready | Bake |
| --- | --- | --- | --- | --- | --- | --- |
| ts-dashboard f1453e3 | 40607563852 | gru | 308.1 s | 2.4 s | 7.8 s | 5 min 0.2 s |
| ts-dashboard fd4c63a | 40610281915 | gru | 310.2 s | 4.7 s | 10.1 s | 5 min 0.0 s |
| ts-dashboard 4622fbe | 40610910656 | gru | 309.8 s | 3.3 s | 9.7 s | 5 min 0.0 s |
| ts-auth 6475a24 | 40610845596 | gru | 318.1 s | 9.3 s | 24.0 s | 5 min 0.0 s |
| App release canary 25176ed | 40618041259 | sjc / fra | 300.6 s / 601.4 s | 0.0 s | 0.2 s | 5 min 0.4 s each |
| App release canary 06a5c2f | 40621595018 | sjc / fra | 306.0 s / 608.9 s | 4.4 s | 5.5 s | 5 min 0.4 s each |
| App release canary 90aefd0 | 40637243210 | sjc / fra | 303.0 s / 605.2 s | 1.9 s | 3.0 s | 5 min 0.0 s each |

The canary job took 10-15 min and the Multi-region mesh check 4-15 min
(90aefd0: 15 min 21 s).

## After: 30-second bake (#200, live from aa14b59)

| Release | Run | Region | Total | Region's own time | Pull | Ready | Bake |
| --- | --- | --- | --- | --- | --- | --- | --- |
| App release canary aa14b59 | 40653518349 | sjc | 33.4 s | 33.4 s | 1.8 s | 3.4 s | 30.0 s |
| | | fra | 65.6 s | 31.0 s | 1.9 s | 1.0 s after submit | 30.0 s |
| App release canary 7add471 | 40662775803 | sjc | 39.3 s | 39.3 s | 2.0 s | 9.3 s (created anew) | 30.0 s |
| | | fra | 71.0 s | 30.7 s | 1.8 s | 0.7 s after submit | 30.0 s |
| ts-dashboard 1cb6b50 | 40654678572 | sjc | 167.0 s | 167.0 s | 2.6 s | 136.5 s (CPU, see below) | 30.4 s |
| | | fra | 208.3 s | 40.1 s | 2.6 s | 9.5 s after submit | 30.4 s |
| | | gru | 243.6 s | 34.7 s | 2.4 s | 4.5 s after submit | 30.1 s |
| ts-dashboard 37ae5d3, rollback leg | 40651907119 attempt 2 | gru / sjc / fra | 30.6 / 31.0 / 31.0 s | same | 0.0 s | 0.2-0.4 s | 30.3-30.6 s |
| ts-auth 9d6cfc0 | terrascale 40661010360 | gru | 78.3 s | 78.3 s | 6.3 s | 9.5 s after submit | 66.0 s (dependency recovery) |

| Orchestrator self-update | Run | gru | sjc | fra |
| --- | --- | --- | --- | --- |
| 796fd20 (#192) | 40628570040 | 11.9 s | 7.5 s | 20.2 s |
| aa14b59 (#201) | 40652574303 | 10.5 s | 8.5 s | 10.9 s |
| 7add471 (#202) | 40661626807 | 10.5 s | 7.7 s | 10.9 s |

Self-update times are from push to the region serving the new binary.

Jobs: App release canary 92 s (aa14b59) and 89 s (7add471). Multi-region mesh
check 1 min 51 s (aa14b59) and 1 min 49 s (7add471).

## Against the target

- **60 s per region: met** for the canary (31-39 s per region), the mesh check
  and the orchestrator self-update (7.5-20.2 s). ts-dashboard's own region time
  was 35-40 s, and the rollback leg 31 s.
- **Missed** twice:
  - ts-dashboard 1cb6b50 in sjc (167 s): the start-first candidate could not be
    placed for 2 min. A 2-CPU host advertises 1750 mCPU; TerraBase (1000), the
    old dashboard task (500) and the canary and whoami (100) left 150 mCPU, and
    the candidate needs 200. Removing the test services unblocked it. Code fix
    pending, E16 in [deploy errors](../deploy-errors-20261027.md).
  - ts-auth 9d6cfc0 (78 s): its bake spent 36 s in dependency recovery while
    the dashboard's readiness followed ts-auth's own restart.
- **10 s warm app deploy: met** by readiness, which comes 0.2-9.5 s after
  submit when the image is already on the host. The 30 s bake comes on top,
  so the release a person sees takes about 35-40 s per region.

## Sample counts

The goal is 3 consecutive releases per service.

| Service | Samples so far | Status |
| --- | --- | --- |
| App release canary | 2 | The third arrives with the next main build. |
| Orchestrator self-update | 3 consecutive | 7.5-20.2 s per region. |
| ts-dashboard | 1 clean, plus 1 rollback leg | Releases only on a push to its main; a `workflow_dispatch` skips the release step. |
| ts-auth | 1 | Releases only when terrascale changes ts-auth. |

Both app services get more samples from their next pushes; this file grows with them.
