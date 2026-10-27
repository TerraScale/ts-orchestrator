# Deploy errors and fix plan (2026-10-27)

Target: every green main build deploys itself to gru, sjc and fra in 60 s or
less per region, an app deploy takes 10 s or less on a warm host, and no deploy
needs a switch or a hand step. This page lists the errors that block that
target, with the evidence and the fix for each. It is updated as each fix
lands.

Status: FIXED (merged and proven live), LIVE (production repaired, code fix
in review), OPEN.

| # | Error | Evidence | Root cause | Fix | Status |
| --- | --- | --- | --- | --- | --- |
| E5 | #182 dashboard (9463) refused on all controllers 15 h after merge | #182 was running (binary installed 2026-10-26 22:48Z). Journal: `create Vault secret <region>-1-orch-dashboard-token failed` every 35 s | `ts-orch-hosts-vault` let hosts create only `ts-orch-mesh-key` and `ts-orch-join-<region>`. The Vault error hid the OCI status | `regionhost.statements` grants each region's dashboard token. Vault list/create errors name the OCI status and code. Live policy converged 14:07Z, so 9463 answers 401 without a token on all 3 hosts | LIVE |
| E12 | ts-orch edge logs ERROR every 5 s on all hosts: `listen tcp 127.0.0.1:8081: address already in use` | `ss`: `systemd-socket-proxyd` (`fr1-terrabase-loopback.socket`) held 127.0.0.1:8081 | The hand-installed shortcut that #186 replaces was never removed. ts-auth and ts-dashboard lost TerraBase for every TerraBase restart (no handoff wait) | Units removed on gru, sjc, fra 14:09-14:10Z. ts-orch now binds 8081 on all 3 hosts | FIXED |
| E4 | ts-orch self-update failed 4 of the last 14 main deploys | run 40270882423 (93a7153, docs only): installed, then `timed out waiting for the region to serve` on all regions. Runs 40277974963, 40285522860, 40326352496: `link ... .prev: operation not permitted` | No automatic rollback: after the timeout an operator restored `.prev` and ran `chattr +i` on the binary (sudo journal 04:56Z). The pin then rejected every install until 14:13Z | Host-side rollback after a failed start or ready deadline, `rolled_back` push state, clear error for an immutable binary, cause of the 3 min serve timeout | OPEN |
| E1 | ts-auth release fails `deployment is stale or changes an already approved run`; Deployment lag guard red | terrascale run 40418667987: attempt 1 approved digest ff2dfc4a, failed readiness (HTTP 503) and rolled back; attempt 2 rebuilt digest 4c5794ac under the same run. Lag guard 40484252276 checks workflow results, not live tasks | `swarmruntime/service_deployment.go:46` refuses a new digest for an already approved run, and builds are not reproducible, so a rerun after a rollback can never deploy | Admit a higher attempt of the same run once the earlier attempt no longer serves. Find the attempt 1 readiness 503 separately | OPEN |
| E2 | ts-dashboard gru `release superseded during bake` when two pushes overlap | ts-dashboard run 40406726375: bake 70 s, newer run 40406885347 started its bake at 21:46:22 | ts-dashboard groups release concurrency by SHA. `mesh/bake.go:178` fails the older release when the desired entry changes | A release superseded by a newer signed run ends `superseded` and exits 0, so overlapping releases coalesce to the latest | OPEN |
| E3 | Multi-region mesh check red: `sjc service whoami is not ready`, then `earlier region failed`; `apply: nats: connection closed` | run 40505259867: sjc journal `task disk capacity or retained storage is unavailable`. Runs 40414585145, 40415408508: sjc baked healthy, then CI lost NATS at 366 s | Every service reserves a fixed 10 GiB disk (`swarmruntime/service.go:610`), and sjc had about 10 GB below the 95 % line because old images were never removed (E13). `mesh/check.go` waits on one RPC with one credential, which the server expires | Live: unused images pruned (sjc 12 to 24 GB free). Code: image GC, disk reservation sized to the service, and a mesh check that renews its credential and polls | OPEN |
| E6 | gru NetBird server task stuck behind an old container, health 503 | container `ts-qbrdyjxm7g8mlvs6wz6ikcxhw` (created 2026-10-22 14:19Z) still runs; 4 newer tasks stay CREATED. Reconciler logs `admitted NetBird peer "ts-fra-1" has no canonical identity in gru-1` | `netbird/manager/peers.go:286` checks admitted peers against the local region only. The 503 and the stuck replacement are under investigation | | OPEN |
| E7 | TerraBase on gru OOM-killed 15 times 2026-10-26 07:01-08:10Z | kernel: `Memory cgroup out of memory ... (terrabase)`, limit 4 GiB; host about 23 GiB | `deploy/m1/services/terrabase.json` caps TerraBase at 4096 MiB | Raise the cap after a capacity check; TerraBase memory profile routed to TerraBase | OPEN |
| E8 | SLO burn alerts for ts-auth and ts-dashboard | Prometheus 14:08Z, 1-day ratio: auth 2.24 %, dashboard 6.77 %; auth about 1,691 HTTP 503 in 24 h. Auth readiness failed at 23:23Z (E1 attempt 1) | E12 (no handoff wait on 127.0.0.1:8081), E7 and failed releases are the measured candidates | Measure again 24 h after E12 and E7 | OPEN |
| E9 | Slow: App release canary 10-15 min, mesh check 4-6 min, app releases about 320 s | ts-dashboard releases: pull 2.5 s, ready 8-10 s, bake 300 s. Canary 40415408515: 600 s release (sjc then fra, 300 s each) after 534 s waiting for a runner | `rollout/bake.go` bakes 5 min per region | Bake 30 s, sampled every 2 s, giving about 41 s per region. Timings published from 3 real deploys per service | OPEN |
| E10 | CI noise | terrascale 40416203211: a real escrow concurrency test failed (`DatabaseEscrowConcurrencyTests.cs:42`), but `ci.yml:490` matches `^failed` and misses BuildKit's `#23 86.53 failed` prefix, so it reports `no failed test`. ts-dashboard 40434424218: 3 Playwright failures (price text, billing journey timeout, BadRequest) | test bugs | Routed to terrascale and ts-dashboard owners | OPEN |
| E13 | Hosts never remove old images | sjc kept 44 TerraBase and 32 app-canary images. Pruning images no container uses freed 12 GB on sjc, 15 GB on fra, 34 GB on gru | no image garbage collection in the runtime | Automatic image GC that keeps current, rollback and referenced images | LIVE |
| E11 | Single points of failure: one manager per region; ts-auth and ts-dashboard only in gru | | plan only | | OPEN |

## Order

E5 and E4 first (the orchestrator must update itself and roll back), then E1 and E2
(app releases fence on the latest run and coalesce), then E3, then E6, E7 and E8,
then E9 timing. Each fix is proven by a green run and a live command; timings
are published from 3 consecutive real deploys per service.
