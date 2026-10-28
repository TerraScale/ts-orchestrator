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
| App release canary 6dc08ce | 40676625209 | sjc | 33.1 s | 33.1 s | 1.9 s | 3.1 s | 30.0 s |
| | | fra | 65.7 s | 31.2 s | 1.8 s | 1.1 s after submit | 30.0 s |
| App release canary 341ec10 | 40683300954 | sjc | 33.0 s | 33.0 s | 1.9 s | 3.0 s | 30.0 s |
| | | fra | 65.2 s | 31.0 s | 1.8 s | 0.9 s after submit | 30.0 s |
| ts-dashboard 1cb6b50 | 40654678572 | sjc | 167.0 s | 167.0 s | 2.6 s | 136.5 s (CPU, see below) | 30.4 s |
| | | fra | 208.3 s | 40.1 s | 2.6 s | 9.5 s after submit | 30.4 s |
| | | gru | 243.6 s | 34.7 s | 2.4 s | 4.5 s after submit | 30.1 s |
| ts-dashboard bb17bac | 40674215363 | sjc | 43.6 s | 43.6 s | 2.5 s | 10.6 s after submit | 30.2 s |
| | | fra | 87.6 s | 43.2 s | 2.7 s | 12.9 s after submit | 30.2 s |
| | | gru | 124.0 s | 34.8 s | 2.3 s | 4.8 s after submit | 30.0 s |
| ts-dashboard 4439248 | 40677942749 | sjc | 45.7 s | 45.7 s | 2.8 s | 12.5 s after submit | 30.2 s |
| | | fra | 87.5 s | 41.1 s | 2.7 s | 10.9 s after submit | 30.2 s |
| | | gru | 121.0 s | 33.0 s | 2.4 s | 3.0 s after submit | 30.0 s |
| ts-dashboard 3ca110d | 40684963005 | sjc | 49.1 s | 49.1 s | 2.5 s | 15.2 s after submit | 31.1 s |
| | | fra | 91.3 s | 41.1 s | 2.8 s | 10.8 s after submit | 30.2 s |
| | | gru | 127.3 s | 34.7 s | 2.3 s | 4.6 s after submit | 30.1 s |
| ts-dashboard 7bd38ad | 40686200710 | sjc | 43.6 s | 43.6 s | 2.9 s | 10.3 s after submit | 30.2 s |
| | | fra | 85.8 s | 41.2 s | 2.7 s | 10.9 s after submit | 30.2 s |
| | | gru | 121.1 s | 34.8 s | 2.5 s | 4.5 s after submit | 30.1 s |
| ts-dashboard 37ae5d3, rollback leg | 40651907119 attempt 2 | gru / sjc / fra | 30.6 / 31.0 / 31.0 s | same | 0.0 s | 0.2-0.4 s | 30.3-30.6 s |
| ts-auth e3a778f | terrascale 40676791472 | gru | 47.1 s | 47.1 s | 6.2 s | 10.6 s after submit | 30.0 s |
| ts-auth 3010780 | terrascale 40677617436 | gru | 45.3 s | 45.3 s | 6.4 s | 11.8 s after submit | 30.0 s |
| ts-auth e99417a | terrascale 40680277219 | gru | 43.7 s | 43.7 s | 6.4 s | 8.3 s after submit | 30.0 s |
| ts-auth a42f65d | terrascale 40680989704 | gru | 42.4 s | 42.4 s | 5.5 s | 6.6 s after submit | 30.1 s |
| ts-auth 445cbf1 | terrascale 40684043364 | gru | 44.2 s | 44.2 s | 5.3 s | 8.5 s after submit | 30.1 s |
| TerraBase 3d160efc (operator re-roll) | 2026-10-28 09:43Z | sjc | 70.7 s | 70.7 s | 0.0 s | 40.3 s after submit | 30.2 s |
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

- **60 s per region: met** by every successful release on the 30 s bake except
  the two listed under "Missed": canary 30.7-39.3 s, ts-auth 42.4-47.1 s, ts-dashboard 33.0-49.1 s (its own
  time in each region) and orchestrator self-update 7.5-20.2 s. The mesh check
  takes under 2 min for all three regions.
- A later region's `submitted` time includes waiting for the earlier regions:
  ts-dashboard's gru row reads 86-93 s submitted, but gru's own time is 33-35 s.
  A whole three-region ts-dashboard release takes about 2 min.
- **Missed** before the fixes:
  - ts-dashboard 1cb6b50 in sjc (167 s): the start-first candidate could not be
    placed for 2 min on a 2-CPU host (E16).
  - ts-auth 9d6cfc0 (78 s): its bake spent 36 s in dependency recovery while
    the dashboard's readiness followed ts-auth's own restart.
  - ts-dashboard 8894ff6, 9bf95a0 and bf10dfa failed: a bake sample was bounded
    by the 2 s poll (E17, fixed by #203).
- **10 s warm app deploy: partly met.** Readiness after submit is 3.0-4.8 s for
  ts-dashboard in gru and 0.7-3.4 s for the canary, but 10.3-15.2 s for
  ts-dashboard on the 2-CPU sjc and fra hosts and 6.6-11.8 s for ts-auth. The
  30 s bake comes on top, so the release a person sees takes 33-49 s per
  region.

## Sample counts

The goal is 3 consecutive releases per service.

| Service | Samples so far | Status |
| --- | --- | --- |
| App release canary | 4 consecutive (aa14b59, 7add471, 6dc08ce, 341ec10) | 33.0-39.3 s per region; fra waits for sjc, then 30.7-31.2 s of its own. |
| Orchestrator self-update | 3 consecutive | 7.5-20.2 s per region. |
| ts-dashboard | 3 consecutive successes (4439248, 3ca110d, 7bd38ad), 5 in all | sjc 43.6-49.1 s, fra 40.1-43.2 s and gru 33.0-35.0 s of their own. bf10dfa (11:31Z) failed on E17, before #203 fixed it. |
| ts-auth | 5 consecutive (e3a778f to 445cbf1) | 42.4-47.1 s in gru, its only region. |

Every service has at least 3 consecutive releases on the 30 s bake.
