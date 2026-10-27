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
| E1 | ts-auth release fails `deployment is stale or changes an already approved run`; ts-auth main undeployed for 9 h or more; Deployment lag guard red | terrascale run 40418667987, lag guard 40484252276 | under investigation | Releases fence on the latest run, not on the first approved one | OPEN |
| E2 | ts-dashboard gru `release superseded during bake` when two pushes overlap | ts-dashboard run 40406726375 | under investigation | Queue overlapping releases and coalesce to the latest instead of failing | OPEN |
| E3 | Multi-region mesh check red: `sjc service whoami is not ready: context deadline exceeded`, then `earlier region failed`, `apply: nats: connection closed` | runs 40505259867, 40415408508, 40414585145 | under investigation | | OPEN |
| E6 | gru NetBird server task stuck about 86 h behind an old container, health 503 | | under investigation | | OPEN |
| E7 | TerraBase on gru OOM-killed 15 times 2026-10-26 07:01-08:10Z | | under investigation | | OPEN |
| E8 | SLO burn: ts-auth 12.8 %, ts-dashboard 2.3 % errors over 1 day | | E12 is a likely cause (no handoff wait on 8081), with E7 | Measure again 24 h after E12 | OPEN |
| E9 | Slow: App release canary 15-20 min, mesh check 4-6 min, ts-dashboard release 82 s | | under investigation | Measure pull, start, ready and bake per phase, then cut each to the target | OPEN |
| E10 | CI noise: terrascale Slow suites `exit 2 with no failed test` (run 40416203211); ts-dashboard Slow Playwright failures | | triage only | Routed to the owning repositories | OPEN |
| E11 | Single points of failure: one manager per region; ts-auth and ts-dashboard only in gru | | plan only | | OPEN |

## Order

E5 and E4 first (the orchestrator must update itself and roll back), then E1 and E2
(app releases fence on the latest run and coalesce), then E3, then E6, E7 and E8,
then E9 timing. Each fix is proven by a green run and a live command; timings
are published from 3 consecutive real deploys per service.
