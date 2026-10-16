# Second main CI fixture repair

Published main `7296e88948ac4cc98d7fcc0065ac5ac011ab1ba3` failed [actual CI run 38970874715](https://github.com/TerraScale/ts-orchestrator/actions/runs/38970874715) in three packages. The guard passed; release retention, image dispatch and fleet deployment were skipped. The complete failed log is retained byte-for-byte in `failed-main-ci.log.gz` (gzip only).

Only four test files change. `checked-source-files.json` proves that integrated code `e0960e38` is byte-identical to the exact passing sources below. Production deadlines, immutable object validation, signed qualification and network isolation remain unchanged.

| Repair | Exact source | Actual check | Result |
| --- | --- | --- | --- |
| Shared rollout cadence | `891fc3132d998a49197eca83561bd649557ad992` | Both region-channel and running-cell executor scenarios, race | PASS 145.680 s; individual 69.43 s and 75.08 s |
| Restore namespace privileges | `3231f2946e30425c1d19efe397bbb68d92becdc6` | Both actual namespace isolation scenarios, race | PASS 5.377 s, zero skips |
| Immutable retry readback budget | `e84414d0febaf2b8cd17532e5c8e9dfad57e75f3` | Complete `TestSignedApplyRegionalHTTPRecovery`, race, count 3 | PASS 22.166 s |

The rollout lab now uses a fixed one-second cadence instead of 200–300 ms. Each channel inventory creates replicated KV watch consumers; the earlier accelerated fixture generated consumer churn and actual CI metadata snapshots took 2.6–3.5 seconds before a prepare deadline expired. All wave, health, soak, signed proof, rollback and seed-last assertions remain.

The namespace fixture reexecutes only itself through passwordless sudo when available, matching the production daemon's root/NEWNET model. It retains the permissive user-namespace route without sudo and fails instead of skipping unsupported isolation. The actual local check reports euid 0, NEWNET only, isolated private traffic and same-namespace rejection. Ubuntu's exact AppArmor denial is inferred, not verified from audit logs; actual CI still must confirm the fix.

The release test retains the initial 500 ms injected-failure budget. Only successful retries receive five seconds for exact digest readback of the real binary after an expected identical-object conditional-create 412. Signed SDK HTTP, immutable bytes/create counts, cancellation and tamper guards remain.

Commands ran at local low priority, GOMAXPROCS=2 and GOFLAGS=-p=2, in their existing serialized check lanes:

```sh
go test -race ./internal/app -run '^(TestReleaseChannelRollsCIReleasesOutRegionByRegion|TestRolloutExecutorUpdatesARunningCell)$' -count=1 -timeout=8m -v
go test -race ./internal/terrabase -run '^TestRestoreNamespace(CommandIsolatesBeforeExec|HasOnlyLoopbackAndLocalTraffic)$' -count=1 -timeout=90s -v
go test -race ./internal/release/cli -run '^TestSignedApplyRegionalHTTPRecovery$' -count=3 -timeout=120s
```

Diff whitespace and zero-configuration checks pass against the published baseline. These focused checks do not establish whole-repository CI, native ARM image runtime, broad refactor completion or production acceptance. The actual CI run after publication remains authoritative.
