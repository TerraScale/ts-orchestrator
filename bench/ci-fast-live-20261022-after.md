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
| Qualified QCOW2 image | deleted | n/a | n/a | n/a | No live consumer: all four live instances use stock Ubuntu; shared final-byte verification retained |
| CodeQL/schedule | 0/3 | pending | pending | pending | Weekly security coverage retained |
| SLO/PR | 0/3 | pending | pending | pending | Duplicate main run removed |
| Deployment lag guard | deleted | n/a | n/a | n/a | Obsolete repo/object-store checks replaced by every-release pinned live-version proof and daily mesh proof |
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
