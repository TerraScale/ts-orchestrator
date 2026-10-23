# ts-orchestrator BEFORE snapshot (2026-10-23 UTC)

Collected one `gh run list -L 100 --json` per 14 registered workflows. Values below are minutes. Run-list elapsed is `updatedAt - startedAt`, an API lifecycle proxy, **not** first-job-to-last-job wall. Run-list wait is `startedAt - createdAt`, **not** runner queue wait. Runner minutes and exact wall require jobs metadata; unavailable entries are deliberately unclaimed. Histories span changing implementations and include failures/cancellations.

| Workflow / event | N | Failed | Last three conclusions | Lifecycle elapsed proxy p50 | Start wait proxy p50 |
|---|---:|---:|---|---:|---:|
| app-canary / push | 21 | 15 | success, success, success | 1.38 | 0.00 |
| app-digests / schedule | 1 | 0 | success | 1.25 | 0.00 |
| app-digests / workflow_run | 13 | 7 | failure, success, success | 0.28 | 0.00 |
| ci / merge_group | 35 | 12 | failure, success, success | 13.98 | 0.00 |
| ci / pull_request | 45 | 5 | success, success, success | 18.23 | 0.00 |
| ci / push | 20 | 2 | success, success, cancelled | 20.56 | 0.00 |
| codeql | 0 | 0 | no runs | n/a | n/a |
| codeql-dynamic / dynamic | 1 | 0 | success | 59.57 | 0.00 |
| dependency-graph / dynamic | 1 | 0 | success | 2.93 | 0.00 |
| deploy-lag / schedule | 40 | 40 | failure, failure, failure | 1.11 | 0.00 |
| deploy-lag / workflow_run | 13 | 12 | failure, failure, failure | 1.17 | 0.00 |
| e2e / pull_request | 13 | 12 | failure, failure, failure | 1.02 | 0.00 |
| e2e / schedule | 6 | 6 | failure, failure, failure | 0.81 | 0.00 |
| e2e-m1 / merge_group | 40 | 3 | success, success, success | 3.01 | 0.00 |
| e2e-m1 / pull_request | 52 | 2 | success, success, success | 3.19 | 0.00 |
| e2e-m1 / push | 8 | 0 | success, success, success | 2.92 | 0.00 |
| image / workflow_dispatch | 35 | 33 | failure, failure, failure | 8.35 | 0.00 |
| multi-region / schedule | 2 | 0 | success, success | 7.91 | 0.00 |
| multi-region / workflow_dispatch | 2 | 1 | success, failure | 0.81 | 0.00 |
| multi-region / workflow_run | 39 | 0 | success, success, success | 0.23 | 0.00 |
| prune-releases / schedule | 6 | 6 | failure, failure, failure | 1.50 | 0.00 |
| slo / pull_request | 11 | 0 | success, success, success | 0.53 | 0.00 |
| slo / push | 2 | 0 | success, success | 1.34 | 0.00 |
| w17b-count50 / push | 1 | 0 | cancelled | 14.45 | 0.00 |

## Exact sampled jobs timing

Six jobs metadata requests used; samples chosen for failure diagnosis, not representative medians. Four repo timing calls remain for AFTER. Queue is first non-skipped job start minus run creation; wall is last job end minus first non-skipped start. Runner minutes sum individual non-skipped job durations (unrounded runtime).

| Run | Workflow/event | Exact wall | Queue | Runner minutes |
|---|---|---:|---:|---:|
| [39863591931](https://github.com/TerraScale/ts-orchestrator/actions/runs/39863591931) | App release canary/push | 1.10 | 0.07 | 1.10 |
| [39876914336](https://github.com/TerraScale/ts-orchestrator/actions/runs/39876914336) | TerraScale Orchestrator Go checks/push | 8.48 | 8.03 | 28.07 |
| [39877160282](https://github.com/TerraScale/ts-orchestrator/actions/runs/39877160282) | App digests/workflow_run | 0.32 | 1.43 | 0.32 |
| [39877437451](https://github.com/TerraScale/ts-orchestrator/actions/runs/39877437451) | TerraScale Orchestrator Go checks/merge_group | 11.45 | 1.12 | 30.97 |
| [39878520681](https://github.com/TerraScale/ts-orchestrator/actions/runs/39878520681) | Qualified GRU ARM64 image/workflow_dispatch | 8.37 | 0.07 | 8.37 |
| [39878573267](https://github.com/TerraScale/ts-orchestrator/actions/runs/39878573267) | Deployment lag guard/workflow_run | 0.93 | 0.07 | 0.93 |

## Diagnosed failures

- App digests 39877160282: `gh release download` fails `no assets to download`; selecting newest ci-* by release creation races upload completion.
- Qualified GRU ARM64 image 39878520681: qualification fixture env absent (`TS_TERRABASE_SERVER`, `TS_TERRABASE_BINARY`, D11 Rust/public artifact, admitted native validator). External TerraBase binary testing also conflicts with workspace policy.
- App release canary 39863591931: GRU succeeded; SJC/FRA rolled back (`ROLLBACK_STARTED`, task early termination); current last three canary runs succeed. This older log does not establish underlying host task cause.
- Deployment lag guard 39878573267: script reports `6 lag/proof failures`; no individual failures printed in failed step log. Needs issue/report evidence before claiming root cause.
- Main Go checks merge_group 39877437451: offline image material command exceeds 180-second deadline; dashboard compressed asset reads exceed context deadline; edge postgres SSLRequest fails. These symptoms occur under 6 race subprocess jobs on a two-core runner; concurrency pressure is suspected, not proven.

## API budget

- Workflow inventory: 1 call. Run lists: 14 commands, exactly once per workflow, 100 max each.
- Jobs/timing: 6 calls: 39878573267, 39863591931, 39877160282, 39878520681, 39876914336, 39877437451.
- Failed log commands: 5 bounded `gh run view --log-failed` calls; raw local logs remain /tmp/ts-orch-failed-ID.log and are not committed. No CI triggers/poll loops.
