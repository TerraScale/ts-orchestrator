# ZDT offline worker boot-volume install — rehearsal timings (2026-11-06)

Plan v4 (`.cos/zdt-20261105/deploy-plan-v2.md`). Clones only: each repeat cloned
the live worker boot volume, attached it to the region's founder, ran the install,
verified, detached and deleted it. Production volumes and instances were only read.
Three measured repeats per region per run, regions in parallel (OCI CLI from beta,
founder SSH). Run A: candidate `dfa837619d76`. Run B: final `2ccab3fdef93`
with verify-rw and the instance-bound drive. Results: A 9/9, B 9/9 PASS; every
founder checked clean after each repeat.

| Step | Run | Min s | Median s | Max s |
| --- | --- | ---: | ---: | ---: |
| Clone stopped-source volume (live source here) | A | 12.0 | 12.9 | 21.2 |
| Clone stopped-source volume (live source here) | B | 12.1 | 17.0 | 20.8 |
| Attach clone rw to founder | A | 17.5 | 20.5 | 37.8 |
| Attach clone rw to founder | B | 17.3 | 20.9 | 37.7 |
| Find disk + mount | A | 1.0 | 3.0 | 3.6 |
| Find disk + mount | B | 0.9 | 2.9 | 3.6 |
| pins-offline + manager cross-check | A | 1.0 | 5.5 | 6.3 |
| pins-offline + manager cross-check | B | 1.0 | 5.4 | 5.9 |
| offline-install (arm, binary, unit) | A | 7.8 | 10.1 | 10.6 |
| offline-install (arm, binary, unit) | B | 7.4 | 9.9 | 10.4 |
| offline-verify on rw mount | B | 0.6 | 2.8 | 3.1 |
| Unmount | A | 0.5 | 2.7 | 2.9 |
| Unmount | B | 0.5 | 2.7 | 2.9 |
| Detach from founder | A | 19.8 | 33.1 | 37.3 |
| Detach from founder | B | 17.0 | 20.5 | 36.7 |
| Reattach read-only (rehearsal only) | A | 20.4 | 33.5 | 37.6 |
| Reattach read-only (rehearsal only) | B | 17.2 | 20.4 | 33.6 |
| Mount ro + offline-verify (rehearsal only) | A | 7.4 | 11.7 | 12.2 |
| Mount ro + offline-verify (rehearsal only) | B | 7.3 | 11.7 | 12.4 |
| Detach (rehearsal only) | A | 20.0 | 33.1 | 37.2 |
| Detach (rehearsal only) | B | 17.1 | 20.5 | 36.8 |
| Delete clone | A | 3.9 | 7.0 | 11.7 |
| Delete clone | B | 4.1 | 4.7 | 8.6 |

Production forward path per worker (clone → detach): run A 73.2–118.6 s;
run B including verify-rw 78.3–102.7 s. OCI attach/detach dominate,
with occasional 33–38 s outliers. Not measured (no new compute allowed): the
boot-volume swap on a STOPPED instance, START, and first boot (planned ≤160 s).
Raw: `.cos/zdt-20261105/qualification/v6-offline-rehearsal-{a,b}.json`.
