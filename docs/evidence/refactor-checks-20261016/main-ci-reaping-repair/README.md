# Stopped launcher completion check

[Actual main CI 38974130841](https://github.com/TerraScale/ts-orchestrator/actions/runs/38974130841) checked published main `8a26863b552a1495baa48f13013b16054f16eb41`. The zero-configuration guard passed. All three previously failing packages passed: every app shard, release/cli (23.292 s), and terrabase (7.054 s). The only remaining package failure was runtimepriority: `TestScopeLauncherRunsDetachedAndReapsOnStop`, line 160, reported "stopped launcher was not reaped". Release retention, image and fleet deployment were skipped. The complete failed log is retained byte-for-byte as gzip.

The launcher waiter sends `cmd.Wait()`'s result to a buffered channel before closing it. `stop` consumes that result after the process has been reaped, then can return before the waiter goroutine executes `close`. The test's immediate nonblocking receive could run in that notification gap. Production already reaps the process; no production behavior changes.

One test line now waits for completion or the existing five-second cleanup context instead of failing immediately. The detached-start, running-before-stop and completion assertions remain. There is no sleep, new timeout, bypass or feature setting.

Exact clean source `90260264102e5f0c813c692516c3014c5df4b41d` passed:

```sh
env GOMAXPROCS=2 GOFLAGS=-p=2 nice -n 19 go test -race ./internal/runtimepriority -run '^TestScopeLauncherRunsDetachedAndReapsOnStop$' -count=100 -timeout=120s
```

Actual result: exit 0, 100 repetitions, package 1.130 s; outer bound 180 s. `checked-source-files.json` proves the integrated test matches that exact passing source. The shared Short-B lane was released; no duplicate runner was used.

Diff whitespace and zero-configuration checks pass against the published baseline. This focused result does not establish whole-repository CI, native/live acceptance or broad refactor completion. Actual CI after publication must still confirm the candidate.
