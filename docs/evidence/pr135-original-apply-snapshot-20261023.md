# PR135: original Apply snapshot through metadata completion

Source baseline: `55353f46dcee1f19739bc6c9b4d224b72956ac8b`.
Local verification: 2026-10-23, existing `fix/ku-security-deploy` worktree.

## Contract

`Applier.Apply` returns the service snapshot produced by its initial
`ApplyServiceSpec` call. Reconciliation carries that snapshot and its selected
`ServiceSpec` through `handleApply` into `Wait`. Keeping the selected spec also
keeps the original deployment floor instead of reading a later desired state.

`CompleteServiceSpec` requires this original snapshot and never recaptures a
baseline. Its existing comparison pins the original service ID and full spec
across completion retries and SwarmKit CAS conflicts. A removed or replaced
service is rejected before creation or update. The existing writer lock is
released between completion retries.

No admission or full-spec comparison was weakened. The 120-second data grace,
exact readiness checks and PR132 wait/rollback behavior are unchanged.

## Regression coverage

The production mesh request handler and production `swarmApplier.Apply/Wait`
run against an in-memory SwarmKit control fixture; container preparation is
stubbed. All eleven existing completion scenarios remain. Four added scenarios
intervene before completion's first service read: a verified equal-generation
mesh winner with changed hostnames, a newer operator, removal and replacement.
Every superseded request must return an error without altering the intervening
service. The equal-generation winner is selected with production `mergeState`.

The focused deferral test retains both initial-read and CAS-retry cases.
A missing original snapshot is explicitly rejected without reading runtime state.
Fake/evidence appliers implement the new contract; the direct deployment-floor
fixture now supplies its existing `gru-1` node identity.

## Local results

All Go commands ran at `nice -n 19`.

| Check | Result |
| --- | --- |
| Full mesh package, 23 top-level tests | PASS, 46.796 s |
| Deferred-metadata regression, 15 scenarios | PASS |
| Focused Swarm selection, 18 top-level tests | PASS, 0.430 s |
| Temporary overlay restoring fresh baseline capture | Expected FAIL: routing and replacement each caused one unwanted write |
| `git diff --check` | PASS |

Commands:

```sh
nice -n 19 go test ./internal/natscell/mesh -count=1 -v
nice -n 19 go test ./internal/swarmruntime -run 'Test(ServiceSpec|WaitServiceSpec|CompleteServiceSpec|SignedServiceFinalMutationGuard|ServiceIntentGeneration|ServiceMetadataRollout|HostnameClaimedByOther)' -count=1 -v
```

Local logs: `/tmp/pr135-original-snapshot-mesh-full.log`,
`/tmp/pr135-original-snapshot-mesh-focused.log`,
`/tmp/pr135-original-snapshot-swarm-focused.log` and
`/tmp/pr135-original-snapshot-negative.log`. The negative check used
`/tmp/pr135-original-snapshot-overlay.json`; it did not edit repository sources.

No push, GitHub/CI action, Ku action, credential access or live change was made.
These results do not establish live containerd or production deployment health.
