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
| Image/dispatch | 0/3 | pending | pending | pending | Missing native/enrollment and signed final-byte fixtures; security gate retained |
| CodeQL/schedule | 0/3 | pending | pending | pending | Weekly security coverage retained |
| SLO/PR | 0/3 | pending | pending | pending | Duplicate main run removed |
| Deployment lag guard | deleted | n/a | n/a | n/a | Obsolete repo/object-store checks replaced by every-release pinned live-version proof and daily mesh proof |
| Release pruning | deleted | n/a | n/a | n/a | No authoritative live/rollback pins; preserve releases rather than guess deletion safety |

## Real merge-to-live proof

Pending. Record PR `mergedAt`, exact merged SHA, and every successful region's `observed_at` from the release-push JSONL artifact. Difference is end-to-end merge-to-observed-live time, including queue, compilation, publication and rollout. Failed or missing region observations never count as live.

The 120-second data-task grace and rollback implementation are unchanged. No production data operations are part of this change.
