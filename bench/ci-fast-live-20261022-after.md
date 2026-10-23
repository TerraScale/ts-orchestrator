# ts-orchestrator AFTER evidence

Not yet measured. Acceptance requires three real runs per affected workflow/event and a real deployment; no result is inferred from syntax validation.

| Workflow/event | AFTER runs | Wall p50 | Queue p50 | Runner minutes p50 | State |
|---|---:|---:|---:|---:|---|
| CI/pull_request | 0/3 | pending | pending | pending | Target test <=8 min |
| CI/merge_group | 0/3 | pending | pending | pending | Full coverage now before main |
| CI/push main | 0/3 | pending | pending | pending | Build/deploy only |
| M1/PR and merge_group | 0/3 | pending | pending | pending | Required name preserved |
| E2E/PR and schedule | 0/3 | pending | pending | pending | HTTP fakes; no external TerraBase binary |
| App canary/push | 0/3 | pending | pending | pending | Publication-to-live <=2 min |
| App digests/workflow_run and schedule | 0/3 | pending | pending | pending | Asset readiness race repaired |
| Multi-region/workflow_run and schedule | 0/3 | pending | pending | pending | Existing pinned mesh proof |
| Qualified QCOW2 image | deleted | n/a | n/a | n/a | No observed serving consumer; managed-image admission and final-byte verification retained |
| CodeQL/schedule | 0/3 | pending | pending | pending | Weekly security coverage retained |
| SLO/PR | 0/3 | pending | pending | pending | Duplicate main run removed |
| Deployment lag guard/workflow_run and schedule | 0/3 | pending | pending | pending | Retain #130 live M1 guard; daily plus after main delivery; unused OCI credential setup removed |
| Release pruning | deleted | n/a | n/a | n/a | No authoritative live/rollback pins; preserve releases rather than guess deletion safety |

## Real merge-to-live proof

Pending. Record PR `mergedAt`, exact merged SHA, and every successful region's `observed_at` from the release-push JSONL artifact. Difference is end-to-end merge-to-observed-live time, including queue, compilation, publication and rollout. Failed or missing region observations never count as live.

The 120-second data-task grace and rollback implementation are unchanged. No production data operations are part of this change.

## Five-repeat timing-sensitive test proof

15/15 targeted repeats passed on delta, 0 failures, with the process restricted to CPUs 0 and 1, GOMAXPROCS=2, go test -race -p=2 -parallel=2 -count=5. Elapsed 353 seconds including cold compilation. Tested commit b38adeb5c841db167f529fb5d941e2987b3f4de0; later image-pipeline removal does not change these runtime tests or the bounded CI concurrency settings.

| Test | Passed | Individual elapsed seconds |
|---|---:|---|
| TestEdgeIssuesCertificateAndProxies | 5/5 | 6.04, 9.00, 12.67, 8.37, 4.19 |
| TestEveryPageStreamCarriesChrome | 5/5 | 2.86, 0.73, 0.73, 0.72, 0.72 |
| TestOfflineDeploymentMaterialNeverBaked | 5/5 | 97.00, 32.59, 32.57, 32.19, 31.90 |

Runtime deadlines and assertions are unchanged. This proves the repeated test outcomes under the stated two-CPU limit, not GitHub queue or deployment speed.

## Failed candidate and corrective selection

Candidate `cfce4cf7fba69eda524cedfb9f1bd834773fb949`, [run 39887476360](https://github.com/TerraScale/ts-orchestrator/actions/runs/39887476360), failed: `verify/change` exceeded its 30-minute job limit; aggregate `test` correctly failed on cancellation. The main race cache restored from `ccbc2736670ba5dca52ca7e7ca37d071aab7e251`; this was not a cache miss. The log reported 191/191 packages selected, 120 shards, two CPU subprocesses and one idle subprocess. Known `.github/` and image-script paths had no Go package ancestor and incorrectly forced all-package PR selection. The 116 completed shard durations sum to 1,736 serial seconds; the unsharded package group was unfinished when cancelled.

From the observed run/check timestamps: queue 1.67 minutes (02:03:33 → 02:05:13 UTC), wall 30.95 minutes (first job start → aggregate completion at 02:36:10), runner runtime 30.35 minutes (30:18 verify/change plus 3 seconds aggregate). These are one failed candidate's measurements, not an AFTER median or a speedup claim. They use existing check metadata, not an additional jobs/timing request.

Correction: map CI/workflow paths and the specific shared image scripts to their real test consumers before taking reverse test dependencies. Selection contracts passed in 40.970 seconds; the actual-deleted-script contract passed in 14.508 seconds. Unknown paths retain all-package fallback; merge-group still runs the complete full tier. No coverage, assertion or runtime deadline is removed to meet a number.

The late hostvolume orphan did not establish a hang: the exact candidate package passed once in 1.382 seconds and five repeats in 5.424 seconds on delta. No hostvolume code or assertions were changed.

## Successful selective candidate and remaining timing floor

Candidate `e4f114448a89c3565d57477b26f919c8c1e38040`, [run 39891335290](https://github.com/TerraScale/ts-orchestrator/actions/runs/39891335290), passed both required checks. CI selected 24/192 packages and 20 race shards, using two CPU worker processes and one idle process. The restored cache came from main `0e468b9026944d538e5b7b2c4a1ef4ef8bc54772`.

| Candidate/event | Queue | Wall | Runner runtime | Required test |
|---|---:|---:|---:|---|
| e4f1144 / pull_request | 0.05 min | 12.53 min | 10.45 min | success; above 8-minute target |

Run created 02:45:44 UTC; verification started 02:45:47 and completed 02:56:10. A separate four-second aggregate job started 02:58:15 and completed 02:58:19, adding 2m05s runner queue after verification. Completed race shard durations sum to 1,034 serial seconds, with the unsharded package group taking 359 seconds. These timestamps come from the existing check readiness response and saved logs; no additional jobs/timing request was used. One candidate is not a three-run median.

Correction prepared after this measurement: the PR verification job reports required `test` directly; the non-PR aggregate retains its required name and failure checks. PR workers use the runner's detected CPU count with `GOMAXPROCS=1` per Go process. The full merge-queue matrix is unchanged. Workflow identity/failure-propagation contracts and an independent review pass. Speed and GitHub runner CPU count remain unclaimed until the corrected candidate executes.

## Latest-main guard correction

Main `5b5f7ed27ff1f119805ece4e4b8a3701efbd491e` (#130) repaired deployment-lag checks against actual M1 orchestrator/app release jobs. This supersedes the original deletion rationale. Retain that guard and its tests, run it daily plus after main delivery, and remove only its unused OCI credentials/configuration setup and unused statuses permission. Grant `checks: read` for #130's commit-check API consumer, identified in independent review. No live check coverage is removed.

## One-CPU test-worker repeat proof

15/15 repeats passed on delta at `e4f114448a89c3565d57477b26f919c8c1e38040`, with CPU affinity 0,1,2,3, `GOMAXPROCS=1`, and `go test -race -p=3 -parallel=2 -count=5`. Elapsed 328 seconds, exit 0, no assertions or deadlines changed.

| Test | Passed | Individual elapsed seconds |
|---|---:|---|
| TestEdgeIssuesCertificateAndProxies | 5/5 | 11.65, 13.15, 13.01, 13.24, 12.62 |
| TestEveryPageStreamCarriesChrome | 5/5 | 12.55, 40.91, 1.92, 1.77, 17.70 |
| TestOfflineDeploymentMaterialNeverBaked | 5/5 | 141.01, 61.46, 39.61, 37.58, 32.52 |

The offline fixture deliberately sets its command subprocesses to `GOMAXPROCS=2` in existing code. This proves one Go CPU per test worker under the stated affinity, not one CPU for every descendant. Raw log: `/tmp/ts-orch-onecpu-five-20261023.log` on delta. Latest main #130 changes only the deployment-lag guard and its documentation/tests, not these test families.

## Corrected worker candidate

Candidate `03022a1ebb4bbc50b9f873a1c26096df3020c7a8`, [run 39893598465](https://github.com/TerraScale/ts-orchestrator/actions/runs/39893598465), passed both required checks and all other triggered checks, with no reviews or findings. Runner logs confirmed four CPUs, four race workers, and one Go CPU per worker. Required `test` ran 03:11:12–03:20:13 UTC: wall and runner runtime 9.02 minutes. Creation at 03:10:40 gives 0.53-minute queue wait. The eight-minute target remains unmet by 61 seconds.

The 22-package group took 360 seconds after waiting 78 seconds behind deployment shards. Its estimate was 238 seconds (four explicit package estimates totaling 220 plus eighteen default one-second estimates), versus 290–295-second deployment estimates whose observed durations were 70–81 seconds. The previous successful candidate's same package group took 359 seconds. Update the short-tier default package estimate from one to eight seconds, accounting for observed compilation/setup overhead: the group estimate becomes 364 seconds and existing longest-first scheduling starts it immediately. Full-tier estimates, test membership, cache expressions, assertions and worker limits are unchanged. This is a scheduling correction; speed remains unclaimed until its real run.
